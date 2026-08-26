package kubernetes

import (
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"k8s.io/client-go/kubernetes/fake"
	"pkg.para.party/certdx/pkg/config"
)

var errBoom = errors.New("boom")

func newTLSSecret(namespace, name, annotation string, cert, key []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{certDxDomainAnnotation: annotation},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       cert,
			corev1.TLSPrivateKeyKey: key,
		},
	}
}

func certificate(domains ...string) *config.ClientCertificate {
	return &config.ClientCertificate{Name: "newtest", Domains: domains}
}

func updateCount(clientset *fake.Clientset) int {
	count := 0
	for _, action := range clientset.Actions() {
		if action.Matches("update", "secrets") {
			count++
		}
	}
	return count
}

// Two secrets sharing a domain set must both be patched by a single
// certificate delivery. Regression test for the one-secret-per-cert bug.
func TestUpdatePatchesAllMatchingSecrets(t *testing.T) {
	annotation := "newtest.campuses.cn,*.newtest.campuses.cn"
	clientset := fake.NewClientset(
		newTLSSecret("namespace", "first", annotation, []byte("old-cert"), []byte("old-key")),
		newTLSSecret("namespace", "second", annotation, []byte("old-cert"), []byte("old-key")),
	)
	action := &Action{kubeClient: clientset}

	cert := certificate("newtest.campuses.cn", "*.newtest.campuses.cn")
	if err := action.Update(context.Background(), []byte("new-cert"), []byte("new-key"), cert); err != nil {
		t.Fatalf("Update: %v", err)
	}

	for _, name := range []string{"first", "second"} {
		secret, err := clientset.CoreV1().Secrets("namespace").Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := string(secret.Data[corev1.TLSCertKey]); got != "new-cert" {
			t.Errorf("secret %s tls.crt = %q, want %q", name, got, "new-cert")
		}
		if got := string(secret.Data[corev1.TLSPrivateKeyKey]); got != "new-key" {
			t.Errorf("secret %s tls.key = %q, want %q", name, got, "new-key")
		}
	}
}

// A secret annotated with a subdomain is covered by the certificate's parent
// domain. Note that a literal "*.example.com" entry only matches itself.
func TestUpdateMatchesSecretsCoveredByParentDomain(t *testing.T) {
	clientset := fake.NewClientset(
		newTLSSecret("namespace", "covered", "foo.example.com", []byte("old"), []byte("old")),
	)
	action := &Action{kubeClient: clientset}

	if err := action.Update(context.Background(), []byte("new-cert"), []byte("new-key"), certificate("example.com")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	secret, err := clientset.CoreV1().Secrets("namespace").Get(context.Background(), "covered", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secret.Data[corev1.TLSCertKey]); got != "new-cert" {
		t.Fatalf("tls.crt = %q, want new-cert", got)
	}
}

func TestUpdateSkipsSecretsOutsideTheCertificate(t *testing.T) {
	clientset := fake.NewClientset(
		newTLSSecret("namespace", "other", "other.example.org", []byte("old"), []byte("old")),
	)
	action := &Action{kubeClient: clientset}

	if err := action.Update(context.Background(), []byte("new-cert"), []byte("new-key"), certificate("example.com")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if got := updateCount(clientset); got != 0 {
		t.Fatalf("update calls = %d, want 0", got)
	}
}

func TestUpdateIgnoresSecretsWithoutAnnotationOrWrongType(t *testing.T) {
	noAnnotation := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "namespace", Name: "bare"},
		Type:       corev1.SecretTypeTLS,
	}
	opaque := newTLSSecret("namespace", "opaque", "foo.example.com", []byte("old"), []byte("old"))
	opaque.Type = corev1.SecretTypeOpaque

	clientset := fake.NewClientset(noAnnotation, opaque)
	action := &Action{kubeClient: clientset}

	if err := action.Update(context.Background(), []byte("new-cert"), []byte("new-key"), certificate("example.com")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if got := updateCount(clientset); got != 0 {
		t.Fatalf("update calls = %d, want 0", got)
	}
}

// Rewriting identical material would restart every consuming pod.
func TestUpdateIsNoOpWhenSecretAlreadyCurrent(t *testing.T) {
	clientset := fake.NewClientset(
		newTLSSecret("namespace", "current", "foo.example.com", []byte("new-cert"), []byte("new-key")),
	)
	action := &Action{kubeClient: clientset}

	if err := action.Update(context.Background(), []byte("new-cert"), []byte("new-key"), certificate("example.com")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if got := updateCount(clientset); got != 0 {
		t.Fatalf("update calls = %d, want 0", got)
	}
}

func TestUpdateRejectsEmptyMaterial(t *testing.T) {
	action := &Action{kubeClient: fake.NewClientset()}
	if err := action.Update(context.Background(), nil, []byte("key"), certificate("example.com")); err == nil {
		t.Fatal("expected error on empty fullchain")
	}
	if err := action.Update(context.Background(), []byte("cert"), nil, certificate("example.com")); err == nil {
		t.Fatal("expected error on empty key")
	}
}

func TestUpdateReportsPerSecretErrors(t *testing.T) {
	clientset := fake.NewClientset(
		newTLSSecret("namespace", "broken", "foo.example.com", []byte("old"), []byte("old")),
	)
	clientset.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errBoom
	})
	action := &Action{kubeClient: clientset}

	err := action.Update(context.Background(), []byte("new-cert"), []byte("new-key"), certificate("example.com"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected the underlying error to be wrapped, got %v", err)
	}
}

func TestParseDomainsAnnotation(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a.example.com, B.example.com ,a.example.com", []string{"a.example.com", "b.example.com"}},
		{"  ", nil},
		{"", nil},
		{",,", nil},
	}
	for _, tc := range cases {
		got := parseDomainsAnnotation(tc.in)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseDomainsAnnotation(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
