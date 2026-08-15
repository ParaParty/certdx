package kubernetesCertificateUpdater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"pkg.para.party/certdx/pkg/api"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
)

func TestDuplicateDomainSecretsShareWatchAndAllUpdate(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if err := json.NewEncoder(w).Encode(api.HttpCertResp{
			RenewTimeLeft: time.Hour,
			FullChain:     []byte("new-cert"),
			Key:           []byte("new-key"),
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	domains := []string{"newtest.campuses.cn", "*.newtest.campuses.cn"}
	newSecret := func(name string) corev1.Secret {
		return corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "namespace",
				Name:        name,
				Annotations: map[string]string{certDxDomainAnnotation: "newtest.campuses.cn,*.newtest.campuses.cn"},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       []byte("old-cert"),
				corev1.TLSPrivateKeyKey: []byte("old-key"),
			},
		}
	}
	first := newSecret("first")
	second := newSecret("second")

	daemon := client.MakeCertDXClientDaemon()
	daemon.Config.Http.MainServer.Url = server.URL
	daemon.Config.Certifications = []config.ClientCertification{{Name: "newtest", Domains: domains}}

	updater := MakeKubernetesReplaceCertificate(&k8sCertsUpdateCmd{})
	updater.certDXDaemon = daemon
	updater.kubeClient = fake.NewSimpleClientset(&first, &second)
	if registered := updater.registerWatchAndHandlers(context.Background(), []corev1.Secret{first, second}); registered != 2 {
		t.Fatalf("registered secrets = %d, want 2", registered)
	}

	go daemon.HttpMain()
	defer daemon.Stop()

	done := make(chan struct{})
	go func() {
		updater.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for both secrets to update")
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("certificate requests = %d, want 1", got)
	}
	for _, name := range []string{"first", "second"} {
		secret, err := updater.kubeClient.CoreV1().Secrets("namespace").Get(context.Background(), name, metav1.GetOptions{})
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

func TestRegisterWatchAndHandlersAcceptsWildcardCoveredDomains(t *testing.T) {
	// The shipped config/client_k8s.toml cert pack, which only lists wildcards.
	daemon := client.MakeCertDXClientDaemon()
	daemon.Config.Certifications = []config.ClientCertification{{
		Name:    "domainsToWatch",
		Domains: []string{"*.example.com", "*.mm.example.com"},
	}}

	newSecret := func(name, annotation string) corev1.Secret {
		return corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "edge",
				Name:        name,
				Annotations: map[string]string{certDxDomainAnnotation: annotation},
			},
			Type: corev1.SecretTypeTLS,
		}
	}
	covered := newSecret("covered", "foo.example.com,foo.mm.example.com")
	wildcard := newSecret("wildcard", "*.example.com")
	nested := newSecret("nested", "deep.nested.example.com")
	// A wildcard-only pack carries no apex SAN (RFC 6125), so a secret that
	// wants the apex is not covered by it and must be skipped.
	apex := newSecret("apex", "example.com")

	updater := MakeKubernetesReplaceCertificate(&k8sCertsUpdateCmd{})
	updater.certDXDaemon = daemon
	updater.kubeClient = fake.NewSimpleClientset()

	registered := updater.registerWatchAndHandlers(context.Background(),
		[]corev1.Secret{covered, wildcard, nested, apex})
	if registered != 2 {
		t.Fatalf("registered secrets = %d, want 2 (wildcard cert pack must cover subdomains)", registered)
	}

	pending := updater.pendingWatchNames()
	if len(pending) != 2 || pending[0] != "edge/covered" || pending[1] != "edge/wildcard" {
		t.Fatalf("pending watches = %v, want [edge/covered edge/wildcard]", pending)
	}
	for range pending {
		updater.wg.Done()
	}
}

func TestGetAllCertificatesFromKubernetesFiltersServerSideAndPaginates(t *testing.T) {
	annotated := func(name string) corev1.Secret {
		return corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "edge",
				Name:        name,
				Annotations: map[string]string{certDxDomainAnnotation: "foo.example.com"},
			},
			Type: corev1.SecretTypeTLS,
		}
	}

	kube := fake.NewSimpleClientset()
	var fieldSelectors []string
	var calls int
	kube.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListActionImpl)
		if !ok {
			t.Errorf("unexpected action type %T", action)
			return false, nil, nil
		}
		fieldSelectors = append(fieldSelectors, listAction.GetListRestrictions().Fields.String())
		calls++
		if calls == 1 {
			return true, &corev1.SecretList{
				ListMeta: metav1.ListMeta{Continue: "page-2"},
				Items: []corev1.Secret{
					annotated("first"),
					{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "unannotated"}, Type: corev1.SecretTypeTLS},
				},
			}, nil
		}
		return true, &corev1.SecretList{Items: []corev1.Secret{annotated("second")}}, nil
	})

	updater := MakeKubernetesReplaceCertificate(&k8sCertsUpdateCmd{})
	updater.kubeClient = kube

	got, err := updater.getAllCertificatesFromKubernetes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("list calls = %d, want 2 (the continue token must be followed)", calls)
	}
	for _, selector := range fieldSelectors {
		if selector != "type=kubernetes.io/tls" {
			t.Fatalf("field selector = %q, want type=kubernetes.io/tls", selector)
		}
	}
	if len(got) != 2 || got[0].Name != "first" || got[1].Name != "second" {
		t.Fatalf("secrets = %v, want the annotated secrets of both pages", got)
	}
}

func TestWaitReplaceTaskTimeoutReportsPendingAndErrors(t *testing.T) {
	updater := MakeKubernetesReplaceCertificate(&k8sCertsUpdateCmd{})
	updater.wg.Add(1)
	defer updater.wg.Done()
	updater.markPending("edge/never-delivered")
	updater.taskErr = append(updater.taskErr, fmt.Errorf("edge/failed: update rejected"))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := updater.waitReplaceTask(ctx)
	if err == nil {
		t.Fatal("expected wait to fail")
	}
	if !strings.Contains(err.Error(), "edge/never-delivered") {
		t.Errorf("error %q does not name the pending secret", err)
	}
	if !strings.Contains(err.Error(), "edge/failed: update rejected") {
		t.Errorf("error %q drops the already accumulated per-secret error", err)
	}
}
