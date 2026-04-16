package kubernetesCertificateUpdater

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/appengine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/utils"
)

type KubernetesCertificateUpdater struct {
	cmd *k8sCertsUpdateCmd

	wg           sync.WaitGroup
	taskErr      appengine.MultiError
	taskErrMutex sync.Mutex

	certDXDaemon *client.CertDXClientDaemon
	kubeClient   kubernetes.Interface
}

func MakeKubernetesReplaceCertificate(updaterCmd *k8sCertsUpdateCmd) *KubernetesCertificateUpdater {
	return &KubernetesCertificateUpdater{
		cmd: updaterCmd,

		wg:           sync.WaitGroup{},
		taskErr:      appengine.MultiError{},
		taskErrMutex: sync.Mutex{},

		// certDXDaemon : in certdx init
	}
}

func (r *KubernetesCertificateUpdater) initCertDX() error {
	r.certDXDaemon = client.MakeCertDXClientDaemon()
	err := r.certDXDaemon.LoadConfigurationAndValidateOpt(*r.cmd.certdxConfig, []config.ValidatingOption{
		config.WithAcceptEmptyCertificateSavePath(true),
		config.WithAcceptEmptyCertificatesList(false),
	})
	if err != nil {
		logging.Fatal("Invalid config: %s", err)
	}
	logging.Debug("Reconnect duration is: %s", r.certDXDaemon.Config.Common.ReconnectDuration)

	return nil
}

func (r *KubernetesCertificateUpdater) initKubernetesClient() error {
	k8sConfPath := r.cmd.k8sConfig

	var (
		restConfig *rest.Config
		err        error
	)

	if k8sConfPath == nil || *k8sConfPath == "" {
		// Empty kubeconfig path: let client-go resolve config via its default chain.
		restConfig, err = clientcmd.BuildConfigFromFlags("", "")
	} else {
		restConfig, err = clientcmd.BuildConfigFromFlags("", *k8sConfPath)
	}
	if err != nil {
		logging.Fatal("Build kubernetes config failed, err: %s", err)
		return err
	}

	r.kubeClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		logging.Fatal("Init kubernetes client failed, err: %s", err)
		return err
	}

	return nil
}

func (r *KubernetesCertificateUpdater) InitCertificateUpdater() error {
	err := r.initCertDX()
	if err != nil {
		logging.Error("Failed to initialize certdx: %s", err)
		return err
	}

	err = r.initKubernetesClient()
	if err != nil {
		logging.Error("Failed to initialize kubernetes client: %s", err)
		return err
	}

	return nil
}

func (r *KubernetesCertificateUpdater) InvokeCertificateUpdate(ctx context.Context) error {
	allCerts, err := r.getAllCertificatesFromKubernetes(ctx)
	if err != nil {
		return err
	}

	err = r.updateCertsToWatchList(ctx, allCerts)
	if err != nil {
		return err
	}

	err = r.startCertDXDaemon()
	if err != nil {
		return err
	}

	r.updateCertificate(ctx, allCerts)

	return nil
}

func (r *KubernetesCertificateUpdater) getAllCertificatesFromKubernetes(ctx context.Context) ([]corev1.Secret, error) {
	if r.kubeClient == nil {
		return nil, nil
	}

	raw, err := r.kubeClient.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logging.Error("Failed to list secrets in kubernetes: %s", err)
	}

	ret := make([]corev1.Secret, 0, len(raw.Items))
	for _, secret := range raw.Items {
		if secret.Type != corev1.SecretTypeTLS {
			continue
		}
		if _, ok := secret.Annotations[certDxDomainAnnotation]; !ok {
			continue
		}

		ret = append(ret, secret)
	}

	return ret, nil
}

func (r *KubernetesCertificateUpdater) updateCertificate(ctx context.Context, certs []corev1.Secret) {
	for _, cert := range certs {
		domainsAnnotation := cert.Annotations[certDxDomainAnnotation]
		domains := parseDomainsAnnotation(domainsAnnotation)

		if isDomainsAllowed(r.certDXDaemon, domains) != nil {
			continue
		}

		err := utils.Retry(5, func() error {
			certToUpload, err := r.certDXDaemon.GetCertificate(ctx, utils.DomainsAsKey(domains))
			if err != nil {
				time.Sleep(1500 * time.Millisecond)
				return err
			}

			err = r.replaceCertificateInKubernetes(ctx, cert, certToUpload)
			if err != nil {
				time.Sleep(1500 * time.Millisecond)
				return err
			}

			return nil
		})

		if err != nil {
			logging.Error("Failed to get certificate from certdx for domains: %s after retries, err: %s", strings.Join(domains, ","), err)
		}
	}
}

func (r *KubernetesCertificateUpdater) startCertDXDaemon() error {
	switch r.certDXDaemon.Config.Common.Mode {
	case "http":
		if r.certDXDaemon.Config.Http.MainServer.Url == "" {
			err := fmt.Errorf("http main server url should not be empty")
			logging.Fatal(err.Error())
			return err
		}
		go r.certDXDaemon.HttpMain()
	case "grpc":
		if r.certDXDaemon.Config.GRPC.MainServer.Server == "" {
			err := fmt.Errorf("GRPC main server url should not be empty")
			logging.Fatal(err.Error())
			return err
		}
		go r.certDXDaemon.GRPCMain()
	default:
		err := fmt.Errorf("not supported mode: %s", r.certDXDaemon.Config.Common.Mode)
		logging.Fatal(err.Error())
		return err
	}
	return nil
}

func (r *KubernetesCertificateUpdater) updateCertsToWatchList(ctx context.Context, certs []corev1.Secret) error {
	for _, cert := range certs {
		domainsAnnotation := cert.Annotations[certDxDomainAnnotation]
		domains := parseDomainsAnnotation(domainsAnnotation)

		if isDomainsAllowed(r.certDXDaemon, domains) != nil {
			continue
		}

		watchKey := strings.Join(domains, ",")

		err := r.certDXDaemon.AddCertToWatch(watchKey, domains)
		if err != nil {
			logging.Fatal("Failed to add cert to watch in certdx for domains: %s, err: %s", strings.Join(domains, ","), err)
			return err
		}
	}
	return nil
}

func (r *KubernetesCertificateUpdater) replaceCertificateInKubernetes(ctx context.Context, cert corev1.Secret, newCert *tls.Certificate) error {
	if len(newCert.Certificate) == 0 {
		logging.Error("No certificate chain found for secret %s/%s", cert.Namespace, cert.Name)
		return fmt.Errorf("no certificate chain found for secret %s/%s", cert.Namespace, cert.Name)
	}

	var certPEM []byte
	for _, certDER := range newCert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(newCert.PrivateKey)
	if err != nil {
		logging.Error("Failed to marshal private key for secret %s/%s: %s", cert.Namespace, cert.Name, err)
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	if len(keyPEM) == 0 {
		logging.Error("Failed to encode private key PEM for secret %s/%s", cert.Namespace, cert.Name)
		return fmt.Errorf("failed to encode private key PEM for secret %s/%s", cert.Namespace, cert.Name)
	}

	secretToUpdate, err := r.kubeClient.CoreV1().Secrets(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
	if err != nil {
		logging.Error("Failed to get secret %s/%s before update: %s", cert.Namespace, cert.Name, err)
		return err
	}

	if secretToUpdate.Data == nil {
		secretToUpdate.Data = make(map[string][]byte)
	}
	secretToUpdate.Type = corev1.SecretTypeTLS
	secretToUpdate.Data[corev1.TLSCertKey] = certPEM
	secretToUpdate.Data[corev1.TLSPrivateKeyKey] = keyPEM

	_, err = r.kubeClient.CoreV1().Secrets(cert.Namespace).Update(ctx, secretToUpdate, metav1.UpdateOptions{})
	if err != nil {
		logging.Error("Failed to update kubernetes secret %s/%s: %s", cert.Namespace, cert.Name, err)
		return err
	}

	logging.Info("Updated kubernetes tls secret %s/%s", cert.Namespace, cert.Name)
	return nil
}

func parseDomainsAnnotation(domainListStr string) []string {
	domainList := strings.Split(domainListStr, ",")

	ret := make([]string, 0, len(domainList))
	for _, domain := range domainList {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			ret = append(ret, domain)
		}
	}

	return ret
}

func isDomainsAllowed(certdx *client.CertDXClientDaemon, domains []string) error {
	for _, item := range certdx.Config.Certifications {
		if utils.DomainsAllowed(item.Domains, domains) {
			return nil
		}
	}
	return fmt.Errorf("domains not allowed: %s", strings.Join(domains, ","))
}
