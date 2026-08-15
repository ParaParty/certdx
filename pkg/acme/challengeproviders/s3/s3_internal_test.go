package s3

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"pkg.para.party/certdx/pkg/config"
)

// testProvider wires a HTTPProvider at a local httptest server so the
// request the SDK actually puts on the wire can be inspected.
func testProvider(t *testing.T, acl types.ObjectCannedACL, endpoint string) *HTTPProvider {
	t.Helper()

	awsCfg, err := awsConfig.LoadDefaultConfig(
		context.Background(),
		awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("id", "secret", "")),
		awsConfig.WithRegion("auto"),
	)
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}

	return &HTTPProvider{
		bucket: "bucket",
		acl:    acl,
		client: s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = &endpoint
			// httptest has no wildcard DNS for virtual-host style.
			o.UsePathStyle = true
		}),
	}
}

// TestNewHTTPProviderACL pins how the config's acl field lands on the
// provider: unset keeps the "public-read" certdx <= v0.6.0 hardcoded, an
// explicit empty acl opts out of the header for ACL-disabled buckets.
func TestNewHTTPProviderACL(t *testing.T) {
	empty := ""
	private := "private"

	cases := []struct {
		name string
		acl  *string
		want types.ObjectCannedACL
	}{
		{"unset keeps public-read", nil, types.ObjectCannedACLPublicRead},
		{"explicit empty sends no ACL", &empty, ""},
		{"explicit value passed through", &private, types.ObjectCannedACLPrivate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewHTTPProvider(config.S3Client{Bucket: "bucket", ACL: tc.acl})
			if err != nil {
				t.Fatalf("NewHTTPProvider: %v", err)
			}
			if p.acl != tc.want {
				t.Errorf("acl = %q want %q", p.acl, tc.want)
			}
		})
	}
}

// TestPresentACLHeader pins the S3 ACL behaviour on the wire: buckets created
// since Apr 2023 have ACLs disabled and reject any x-amz-acl header, so an
// empty resolved ACL must send no header at all.
func TestPresentACLHeader(t *testing.T) {
	cases := []struct {
		name   string
		acl    types.ObjectCannedACL
		wantHd string
	}{
		{"empty ACL omits the header", "", ""},
		{"resolved ACL is sent", types.ObjectCannedACLPublicRead, "public-read"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			var seen bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = true
				got = r.Header.Get("X-Amz-Acl")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			p := testProvider(t, tc.acl, srv.URL)
			if err := p.Present("example.com", "token", "keyAuth"); err != nil {
				t.Fatalf("Present: %v", err)
			}
			if !seen {
				t.Fatal("no request reached the test server")
			}
			if got != tc.wantHd {
				t.Errorf("X-Amz-Acl=%q want %q", got, tc.wantHd)
			}
		})
	}
}

// TestCleanUpDeletes checks CleanUp issues the DELETE for the challenge
// path and does not hang on its own context.
func TestCleanUpDeletes(t *testing.T) {
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := testProvider(t, "", srv.URL)
	if err := p.CleanUp("example.com", "token", "keyAuth"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if method != http.MethodDelete {
		t.Errorf("method=%s want DELETE", method)
	}
	if want := "/bucket/.well-known/acme-challenge/token"; path != want {
		t.Errorf("path=%s want %s", path, want)
	}
}
