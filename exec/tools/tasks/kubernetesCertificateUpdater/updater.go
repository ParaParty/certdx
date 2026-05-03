package kubernetesCertificateUpdater

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
)

// Required RBAC: this updater performs a cluster-wide list of secrets and
// reads/writes only the ones annotated with certDxDomainAnnotation. The
// service account running it therefore needs at least:
//
//	apiGroups: [""]
//	resources: ["secrets"]
//	verbs:     ["list", "get", "update"]
//
// granted via a ClusterRole + ClusterRoleBinding (cluster-wide) since the
// list is performed across all namespaces.

type KubernetesCertificateUpdater struct {
	cmd *k8sCertsUpdateCmd

	wg           sync.WaitGroup
	taskErrMutex sync.Mutex
	taskErr      []error

	certDXDaemon *client.CertDXClientDaemon
	kubeClient   kubernetes.Interface

	// daemonErr is written exactly once by the goroutine that runs
	// HttpMain / GRPCMain if the daemon fails to start (e.g. invalid
	// mtls material). waitReplaceTask selects on it so an init failure
	// surfaces immediately instead of hanging until waitDeadline.
	daemonErr chan error
}

func MakeKubernetesReplaceCertificate(updaterCmd *k8sCertsUpdateCmd) *KubernetesCertificateUpdater {
	return &KubernetesCertificateUpdater{
		cmd: updaterCmd,

		wg:           sync.WaitGroup{},
		taskErrMutex: sync.Mutex{},
		daemonErr:    make(chan error, 1),

		// certDXDaemon : in certdx init
	}
}

func (r *KubernetesCertificateUpdater) initCertDX() error {
	r.certDXDaemon = client.MakeCertDXClientDaemon()
	if err := r.certDXDaemon.LoadConfigurationAndValidateOpt(r.cmd.certdxConfig, []config.ValidatingOption{
		config.WithAcceptEmptyCertificateSavePath(true),
		config.WithAcceptEmptyCertificatesList(false),
	}); err != nil {
		return fmt.Errorf("invalid certdx config: %w", err)
	}
	logging.Debug("Reconnect duration is: %s", r.certDXDaemon.Config.Common.ReconnectDuration)
	return nil
}

func (r *KubernetesCertificateUpdater) initKubernetesClient() error {
	// Empty kubeconfig path: let client-go resolve config via its default chain
	// (in-cluster service account, then $KUBECONFIG / ~/.kube/config).
	restConfig, err := clientcmd.BuildConfigFromFlags("", r.cmd.k8sConfig)
	if err != nil {
		return fmt.Errorf("build kubernetes config failed: %w", err)
	}

	r.kubeClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("init kubernetes client failed: %w", err)
	}
	return nil
}

func (r *KubernetesCertificateUpdater) InitCertificateUpdater() error {
	if err := r.initCertDX(); err != nil {
		logging.Error("Failed to initialize certdx: %s", err)
		return err
	}
	if err := r.initKubernetesClient(); err != nil {
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

	registered := r.registerWatchAndHandlers(ctx, allCerts)
	if registered == 0 {
		logging.Warn("No annotated TLS secrets to update; nothing to do")
		return nil
	}

	if err := r.startCertDXDaemon(); err != nil {
		return err
	}
	defer r.certDXDaemon.Stop()

	return r.waitReplaceTask()
}

func (r *KubernetesCertificateUpdater) getAllCertificatesFromKubernetes(ctx context.Context) ([]corev1.Secret, error) {
	if r.kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is not initialized")
	}

	raw, err := r.kubeClient.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets in kubernetes: %w", err)
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

// registerWatchAndHandlers parses each annotated secret, validates its domains
// against the certdx allowlist, and registers a per-secret callback with the
// certdx daemon. The callback fires when the daemon delivers a fresh cert
// (mirroring the txcCertificateUpdater pattern), at which point the kubernetes
// secret is patched. Returns the number of successfully registered secrets.
func (r *KubernetesCertificateUpdater) registerWatchAndHandlers(ctx context.Context, certs []corev1.Secret) int {
	registered := 0
	for i := range certs {
		secret := certs[i] // capture by value for the closure

		domainsAnnotation := secret.Annotations[certDxDomainAnnotation]
		domains := parseDomainsAnnotation(domainsAnnotation)
		if len(domains) == 0 {
			logging.Warn("Skipping secret %s/%s: empty domain annotation", secret.Namespace, secret.Name)
			continue
		}

		if !areDomainsAllowed(r.certDXDaemon, domains) {
			logging.Warn("Skipping secret %s/%s: domains %v not in certdx allowlist",
				secret.Namespace, secret.Name, domains)
			continue
		}

		watchName := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
		r.wg.Add(1)

		var once sync.Once
		handler := func(fullchain, key []byte, _ *config.ClientCertification) {
			// The daemon may invoke this on every renewal. We only care about
			// the first successful delivery for this one-shot run.
			once.Do(func() {
				defer r.wg.Done()
				if err := r.replaceCertificateInKubernetes(ctx, secret, fullchain, key); err != nil {
					r.taskErrMutex.Lock()
					r.taskErr = append(r.taskErr, fmt.Errorf("%s/%s: %w", secret.Namespace, secret.Name, err))
					r.taskErrMutex.Unlock()
				}
			})
		}

		if err := r.certDXDaemon.AddCertToWatchOpt(watchName, domains, []client.WatchingCertsOption{
			client.WithCertificateHandlerOption(handler),
		}); err != nil {
			logging.Error("Failed to add cert to watch for secret %s: %s", watchName, err)
			r.wg.Done()
			continue
		}
		registered++
	}
	return registered
}

func (r *KubernetesCertificateUpdater) startCertDXDaemon() error {
	var run func() error
	switch r.certDXDaemon.Config.Common.Mode {
	case config.CLIENT_MODE_HTTP:
		if r.certDXDaemon.Config.Http.MainServer.Url == "" {
			return fmt.Errorf("http main server url should not be empty")
		}
		run = r.certDXDaemon.HttpMain
	case config.CLIENT_MODE_GRPC:
		if r.certDXDaemon.Config.GRPC.MainServer.Server == "" {
			return fmt.Errorf("GRPC main server url should not be empty")
		}
		run = r.certDXDaemon.GRPCMain
	default:
		return fmt.Errorf("not supported mode: %s", r.certDXDaemon.Config.Common.Mode)
	}
	go func() {
		if err := run(); err != nil {
			// Surface the error to waitReplaceTask via daemonErr (so
			// init failures do not silently hang the outer wait), then
			// cancel the daemon so any other watchers wind down.
			select {
			case r.daemonErr <- err:
			default:
			}
			r.certDXDaemon.Stop()
		}
	}()
	return nil
}

func (r *KubernetesCertificateUpdater) waitReplaceTask() error {
	waitCtx, cancel := context.WithTimeout(context.Background(), waitDeadline)
	defer cancel()

	wgDone := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(wgDone)
	}()

	select {
	case err := <-r.daemonErr:
		return fmt.Errorf("certdx daemon failed: %w", err)
	case <-waitCtx.Done():
		return fmt.Errorf("timeout waiting for kubernetes secrets to be updated")
	case <-wgDone:
		r.taskErrMutex.Lock()
		defer r.taskErrMutex.Unlock()
		if len(r.taskErr) == 0 {
			logging.Info("All kubernetes secrets updated successfully")
			return nil
		}
		return errors.Join(r.taskErr...)
	}
}

func (r *KubernetesCertificateUpdater) replaceCertificateInKubernetes(ctx context.Context, cert corev1.Secret, fullchain, key []byte) error {
	if len(fullchain) == 0 || len(key) == 0 {
		return fmt.Errorf("empty certificate or key")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secretToUpdate, err := r.kubeClient.CoreV1().Secrets(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				logging.Warn("Secret %s/%s no longer exists, skipping update", cert.Namespace, cert.Name)
				return nil
			}
			return fmt.Errorf("get secret before update: %w", err)
		}

		if secretToUpdate.Data == nil {
			secretToUpdate.Data = make(map[string][]byte)
		}

		// No-op skip: avoid triggering pod restarts on consumers that watch
		// this secret if the contents are already current.
		if bytes.Equal(secretToUpdate.Data[corev1.TLSCertKey], fullchain) &&
			bytes.Equal(secretToUpdate.Data[corev1.TLSPrivateKeyKey], key) &&
			secretToUpdate.Type == corev1.SecretTypeTLS {
			logging.Info("Kubernetes tls secret %s/%s already up to date", cert.Namespace, cert.Name)
			return nil
		}

		secretToUpdate.Type = corev1.SecretTypeTLS
		secretToUpdate.Data[corev1.TLSCertKey] = fullchain
		secretToUpdate.Data[corev1.TLSPrivateKeyKey] = key

		if _, err := r.kubeClient.CoreV1().Secrets(cert.Namespace).Update(ctx, secretToUpdate, metav1.UpdateOptions{}); err != nil {
			return err
		}
		logging.Info("Updated kubernetes tls secret %s/%s", cert.Namespace, cert.Name)
		return nil
	})
}

func parseDomainsAnnotation(domainListStr string) []string {
	parts := strings.Split(domainListStr, ",")
	seen := make(map[string]struct{}, len(parts))
	ret := make([]string, 0, len(parts))
	for _, domain := range parts {
		d := strings.ToLower(strings.TrimSpace(domain))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		ret = append(ret, d)
	}
	return ret
}

func areDomainsAllowed(certdx *client.CertDXClientDaemon, domains []string) bool {
	for _, item := range certdx.Config.Certifications {
		if domain.AllAllowed(item.Domains, domains) {
			return true
		}
	}
	return false
}
