package s3_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsS3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/provider/http/s3"
)

func TestS3(t *testing.T) {
	provider, err := s3.NewHTTPProvider(config.S3Client{
		Region:          "ap-beijing",
		PartitionID:     "aws",
		AccessKeyId:     os.Getenv("ACCESSKEYID"),
		AccessKeySecret: os.Getenv("ACCESSKEYSECRET"),
		Bucket:          os.Getenv("BUCKET"),
		URL:             "https://cos.ap-beijing.myqcloud.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := provider.Client().PutObject(context.Background(), &awsS3.PutObjectInput{
		Bucket:       aws.String(os.Getenv("BUCKET")),
		Key:          aws.String("test"),
		Body:         strings.NewReader("xxxxxxx"),
		StorageClass: "STANDARD",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(out)
}
