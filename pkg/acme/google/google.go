package google

import (
	"context"
	"encoding/json"
	"fmt"

	publicca "cloud.google.com/go/security/publicca/apiv1"
	"cloud.google.com/go/security/publicca/apiv1/publiccapb"
	"google.golang.org/api/option"
	"pkg.para.party/certdx/pkg/config"
)

type AcmeExternalAccount struct {
	HmacEncoded string `json:"hmac_encoded"`
	KeyId       string `json:"key_id"`
}

func CreateExternalAccountKeyRequest(config config.GoogleCloudCredential) (AcmeExternalAccount, error) {
	credential, err := json.Marshal(config)
	if err != nil {
		return AcmeExternalAccount{}, err
	}

	project_id, ok := config["project_id"]
	if !ok {
		return AcmeExternalAccount{}, fmt.Errorf("no project id present")
	}

	ctx := context.Background()
	c, err := publicca.NewPublicCertificateAuthorityClient(ctx, option.WithCredentialsJSON(credential))
	if err != nil {
		return AcmeExternalAccount{}, err
	}
	defer c.Close()

	req := &publiccapb.CreateExternalAccountKeyRequest{
		Parent:             fmt.Sprintf("projects/%s/locations/global", project_id),
		ExternalAccountKey: &publiccapb.ExternalAccountKey{},
	}
	resp, err := c.CreateExternalAccountKey(ctx, req)
	if err != nil {
		return AcmeExternalAccount{}, err
	}

	ret := AcmeExternalAccount{}
	ret.KeyId = resp.KeyId
	ret.HmacEncoded = string(resp.B64MacKey)
	return ret, nil
}
