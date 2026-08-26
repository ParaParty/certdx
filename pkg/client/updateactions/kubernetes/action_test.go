package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
	daemon.Config.Certificates = []config.ClientCertificate{{Name: "newtest", Domains: domains}}

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
