package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestHttpCertReqJSONRoundTrip pins the wire format. The struct is part
// of certdx's public contract — any silent field-name change breaks
// mixed-version deployments, so this test fails loudly if a tag drifts.
func TestHttpCertReqJSONRoundTrip(t *testing.T) {
	in := HttpCertReq{Domains: []string{"example.com", "*.example.com"}}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := string(b)
	want := `{"domains":["example.com","*.example.com"]}`
	if got != want {
		t.Fatalf("wire format drift:\n got:  %s\n want: %s", got, want)
	}

	var out HttpCertReq
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip lost data: in=%+v out=%+v", in, out)
	}
}

func TestHttpCertRespJSONRoundTrip(t *testing.T) {
	in := HttpCertResp{
		RenewTimeLeft: 24 * time.Hour,
		FullChain:     []byte("PEM-fullchain"),
		Key:           []byte("PEM-key"),
		Err:           "",
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Spot-check tag names — drift here breaks mixed-version deploys.
	for _, want := range []string{`"renewTimeLeft":`, `"fullchain":`, `"key":`, `"err":`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing wire tag %s in %s", want, b)
		}
	}

	var out HttpCertResp
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip lost data: in=%+v out=%+v", in, out)
	}
}

// TestHttpCertRespErrTagSurvives covers the allowlist-rejection path:
// the server writes {"err":"Domains not allowed"} and the client must
// be able to read it.
func TestHttpCertRespErrTagSurvives(t *testing.T) {
	body := []byte(`{ "err": "Domains not allowed" }`)
	var resp HttpCertResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal allowlist rejection: %v", err)
	}
	if resp.Err != "Domains not allowed" {
		t.Fatalf("Err mismatch: got %q want %q", resp.Err, "Domains not allowed")
	}
	if len(resp.FullChain) != 0 || len(resp.Key) != 0 {
		t.Fatalf("expected empty cert/key on rejection, got fullchain=%d key=%d", len(resp.FullChain), len(resp.Key))
	}
}
