// Package kubernetes is the "kubernetes" update action: it patches
// annotated kubernetes.io/tls secrets in place with renewed material.
//
// Required RBAC: the action performs a cluster-wide list of secrets and
// reads/writes only the ones annotated with certDxDomainAnnotation. The
// service account running it therefore needs at least:
//
//	apiGroups: [""]
//	resources: ["secrets"]
//	verbs:     ["list", "get", "update"]
//
// granted via a ClusterRole + ClusterRoleBinding (cluster-wide) since the
// list is performed across all namespaces.
package kubernetes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/domain"
	"pkg.para.party/certdx/pkg/logging"
)

type Action struct {
	kubeClient kubernetes.Interface
}

func New(profile *config.KubernetesProfile) (*Action, error) {
	// Empty kubeconfig path: let client-go resolve config via its default chain
	// (in-cluster service account, then $KUBECONFIG / ~/.kube/config).
	restConfig, err := clientcmd.BuildConfigFromFlags("", profile.KubeConfig)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes config failed: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("init kubernetes client failed: %w", err)
	}

	return &Action{kubeClient: kubeClient}, nil
}

func (a *Action) Type() string {
	return config.UPDATE_ACTION_KUBERNETES
}

// Update patches every annotated TLS secret whose domains this certificate
// covers. Secrets are listed on each update rather than once at start-up, so
// secrets created or deleted while the daemon runs are picked up.
func (a *Action) Update(ctx context.Context, fullchain, key []byte, c *config.ClientCertificate) error {
	if len(fullchain) == 0 || len(key) == 0 {
		return fmt.Errorf("empty certificate or key")
	}

	secrets, err := a.matchingSecrets(ctx, c.Domains)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		logging.Warn("No annotated TLS secret matches domains %v, nothing to update", c.Domains)
		return nil
	}

	var ret []error
	for _, secret := range secrets {
		if err := a.replaceCertificate(ctx, secret, fullchain, key); err != nil {
			ret = append(ret, fmt.Errorf("%s/%s: %w", secret.Namespace, secret.Name, err))
		}
	}
	return errors.Join(ret...)
}

// matchingSecrets lists kubernetes.io/tls secrets cluster-wide and keeps the
// ones whose domain annotation is covered by the certificate's domains.
func (a *Action) matchingSecrets(ctx context.Context, certDomains []string) ([]corev1.Secret, error) {
	raw, err := a.kubeClient.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets in kubernetes: %w", err)
	}

	ret := make([]corev1.Secret, 0, len(raw.Items))
	for _, secret := range raw.Items {
		if secret.Type != corev1.SecretTypeTLS {
			continue
		}

		annotation, ok := secret.Annotations[certDxDomainAnnotation]
		if !ok {
			continue
		}

		domains := parseDomainsAnnotation(annotation)
		if len(domains) == 0 {
			logging.Warn("Skipping secret %s/%s: empty domain annotation", secret.Namespace, secret.Name)
			continue
		}

		if !domain.AllAllowed(certDomains, domains) {
			continue
		}

		ret = append(ret, secret)
	}
	return ret, nil
}

func (a *Action) replaceCertificate(ctx context.Context, cert corev1.Secret, fullchain, key []byte) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secretToUpdate, err := a.kubeClient.CoreV1().Secrets(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
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

		if _, err := a.kubeClient.CoreV1().Secrets(cert.Namespace).Update(ctx, secretToUpdate, metav1.UpdateOptions{}); err != nil {
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
