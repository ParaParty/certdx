package caddytls

import (
	"encoding/json"
	"testing"

	"pkg.para.party/certdx/pkg/config"
)

func TestJSONConfigKeepsDefaults(t *testing.T) {
	m := (&CertDXCaddyDaemon{}).CaddyModule().New().(*CertDXCaddyDaemon)
	raw := `{"http":{"main_server":{"url":"https://certdx.example/api"}},"certificates":{"site":["example.com"]}}`
	if err := json.Unmarshal([]byte(raw), m); err != nil {
		t.Fatal(err)
	}

	if m.Mode != config.CLIENT_MODE_HTTP || m.ReconnectInterval != "10m" || m.RetryCount != 5 {
		t.Fatalf("common defaults lost: %+v", m.ClientCommonConfig)
	}
	if m.Http.MainServer.AuthMethod != config.HTTP_AUTH_TOKEN {
		t.Fatalf("authMethod = %q, want %q", m.Http.MainServer.AuthMethod, config.HTTP_AUTH_TOKEN)
	}
	if _, ok := m.CertificateDefs.Lookup("site"); !ok {
		t.Fatal("certificate definition not decoded")
	}
}
