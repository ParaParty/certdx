package s3_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsS3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"pkg.para.party/certdx/pkg/acme/challengeproviders/s3"
	"pkg.para.party/certdx/pkg/config"
)

// TestS3 exercises the S3 challenge provider against a live bucket. It is
// skipped unless ACCESSKEYID, ACCESSKEYSECRET, and BUCKET are all set so
// `go test ./...` does not fail on a developer machine without S3
// credentials.
func TestS3(t *testing.T) {
	bucket := os.Getenv("BUCKET")
	accessKey := os.Getenv("ACCESSKEYID")
	accessSecret := os.Getenv("ACCESSKEYSECRET")
	if bucket == "" || accessKey == "" || accessSecret == "" {
		t.Skip("skipping live S3 test: ACCESSKEYID, ACCESSKEYSECRET, BUCKET must all be set")
	}

	provider, err := s3.NewHTTPProvider(config.S3Client{
		Region:          "ap-beijing",
		PartitionID:     "aws",
		AccessKeyId:     accessKey,
		AccessKeySecret: accessSecret,
		Bucket:          bucket,
		URL:             "https://cos.ap-beijing.myqcloud.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := provider.Client().PutObject(context.Background(), &awsS3.PutObjectInput{
		Bucket:       aws.String(bucket),
		Key:          aws.String("test"),
		Body:         strings.NewReader("xxxxxxx"),
		StorageClass: "STANDARD",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(out)
}
