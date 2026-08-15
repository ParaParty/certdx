// Package s3 implements an HTTP provider for solving the HTTP-01 challenge using AWS S3.
package s3

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/go-acme/lego/v4/challenge/http01"
	"pkg.para.party/certdx/pkg/config"
)

// requestTimeout bounds a single S3 API call. lego gives the provider no
// context, so Present/CleanUp derive their own rather than blocking the
// whole challenge on a wedged connection.
const requestTimeout = 30 * time.Second

// HTTPProvider implements ChallengeProvider for `http-01` challenge.
type HTTPProvider struct {
	bucket string
	// acl is the canned ACL applied to the challenge object, already
	// resolved from the config by [config.S3Client.ResolvedACL]. Empty means
	// no ACL header is sent, which is the only thing that works on buckets
	// with ACLs disabled (the default for buckets created since Apr 2023).
	acl    types.ObjectCannedACL
	client *s3.Client
}

func (s *HTTPProvider) Client() *s3.Client {
	return s.client
}

// NewHTTPProvider returns a HTTPProvider instance with a configured s3 bucket and aws session.
// Credentials must be passed in the environment variables. The bucket name
// is required; an empty bucket fails fast rather than producing opaque
// runtime errors deep inside an ACME challenge. The canned ACL follows
// cfg.ResolvedACL: unset means the historical "public-read", an explicit
// empty acl sends no ACL header at all (for buckets with ACLs disabled,
// where public read access comes from the bucket policy instead).
func NewHTTPProvider(cfg config.S3Client) (*HTTPProvider, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 challenge provider: bucket is required")
	}

	credential := credentials.NewStaticCredentialsProvider(cfg.AccessKeyId, cfg.AccessKeySecret, cfg.SessionToken)
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			PartitionID:   cfg.PartitionID,
			URL:           cfg.URL,
			SigningRegion: cfg.Region,
		}, nil
	})

	awsCfg, err := awsConfig.LoadDefaultConfig(
		context.Background(),
		awsConfig.WithCredentialsProvider(credential),
		awsConfig.WithEndpointResolverWithOptions(customResolver),
		awsConfig.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return &HTTPProvider{
		bucket: cfg.Bucket,
		acl:    types.ObjectCannedACL(cfg.ResolvedACL()),
		client: s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.UsePathStyle = false
		}),
	}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)` by creating a file in the given s3 bucket.
func (s *HTTPProvider) Present(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	params := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(strings.Trim(http01.ChallengePath(token), "/")),
		Body:   bytes.NewReader([]byte(keyAuth)),
	}
	// An empty ACL must not put an x-amz-acl header on the wire: buckets with
	// ACLs disabled reject the request outright.
	if s.acl != "" {
		params.ACL = s.acl
	}

	_, err := s.client.PutObject(ctx, params)
	if err != nil {
		return fmt.Errorf("s3: failed to upload token to s3: %w", err)
	}
	return nil
}

// CleanUp removes the file created for the challenge.
func (s *HTTPProvider) CleanUp(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	params := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(strings.Trim(http01.ChallengePath(token), "/")),
	}

	_, err := s.client.DeleteObject(ctx, params)
	if err != nil {
		return fmt.Errorf("s3: could not remove file in s3 bucket after HTTP challenge: %w", err)
	}

	return nil
}
