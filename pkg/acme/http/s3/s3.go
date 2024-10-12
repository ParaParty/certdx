// Package s3 implements an HTTP provider for solving the HTTP-01 challenge using AWS S3.
package s3

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-acme/lego/v4/challenge/http01"
	"pkg.para.party/certdx/pkg/config"
)

// HTTPProvider implements ChallengeProvider for `http-01` challenge.
type HTTPProvider struct {
	bucket string
	client *s3.Client
}

func (s *HTTPProvider) Client() *s3.Client {
	return s.client
}

// NewHTTPProvider returns a HTTPProvider instance with a configured s3 bucket and aws session.
// Credentials must be passed in the environment variables.
func NewHTTPProvider(config config.S3Client) (*HTTPProvider, error) {
	credential := credentials.NewStaticCredentialsProvider(config.AccessKeyId, config.AccessKeySecret, config.SessionToken)
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			PartitionID:   config.PartitionID,
			URL:           config.URL,
			SigningRegion: config.Region,
		}, nil
	})

	cfg, err := awsConfig.LoadDefaultConfig(
		context.TODO(),
		awsConfig.WithCredentialsProvider(credential),
		awsConfig.WithEndpointResolverWithOptions(customResolver),
		awsConfig.WithRegion("auto"),
	)
	if err != nil {
		log.Printf("LoadDefaultConfig error: %v", err)
		return nil, err
	}

	return &HTTPProvider{
		bucket: config.Bucket,
		client: s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.UsePathStyle = false
		}),
	}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)` by creating a file in the given s3 bucket.
func (s *HTTPProvider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()

	params := &s3.PutObjectInput{
		ACL:    "public-read",
		Bucket: aws.String(s.bucket),
		Key:    aws.String(strings.Trim(http01.ChallengePath(token), "/")),
		Body:   bytes.NewReader([]byte(keyAuth)),
	}

	_, err := s.client.PutObject(ctx, params)
	if err != nil {
		return fmt.Errorf("s3: failed to upload token to s3: %w", err)
	}
	return nil
}

// CleanUp removes the file created for the challenge.
func (s *HTTPProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()

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
