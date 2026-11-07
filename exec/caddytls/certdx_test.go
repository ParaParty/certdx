package caddytls

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

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

func TestCaddyfileDomainsNotAllowedFailover(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		directive string
		want      bool
		wantError bool
	}{
		{name: "default"},
		{name: "enabled", directive: "failover_on_domains_not_allowed true", want: true},
		{name: "disabled", directive: "failover_on_domains_not_allowed false"},
		{name: "missing argument", directive: "failover_on_domains_not_allowed", wantError: true},
		{name: "invalid argument", directive: "failover_on_domains_not_allowed invalid", wantError: true},
		{name: "extra argument", directive: "failover_on_domains_not_allowed true false", wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := fmt.Sprintf(`certdx {
	mode http
	http {
		%s
		main_server {
			url https://main.example/api
			token test-token
		}
		standby_server {
			url https://standby.example/api
			token test-token
		}
	}
	certificate site {
		example.com
	}
}`, testCase.directive)
			parsed, err := parseCertDXGlobalOptions(caddyfile.NewTestDispenser(input), nil)
			if testCase.wantError {
				if err == nil {
					t.Fatal("expected invalid directive to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			module := MakeCertDXCaddyDaemon()
			if err := json.Unmarshal(parsed.(httpcaddyfile.App).Value, module); err != nil {
				t.Fatal(err)
			}
			if module.Http.FailoverOnDomainsNotAllowed != testCase.want {
				t.Fatalf("parsed failover = %v, want %v", module.Http.FailoverOnDomainsNotAllowed, testCase.want)
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			if err := module.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			defer module.Stop()
			if got := module.certDXDaemon.Config.Http.FailoverOnDomainsNotAllowed; got != testCase.want {
				t.Fatalf("client failover = %v, want %v", got, testCase.want)
			}
		})
	}
}
