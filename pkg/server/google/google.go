package google

import (
	publicca "cloud.google.com/go/security/publicca/apiv1beta1"
	"cloud.google.com/go/security/publicca/apiv1beta1/publiccapb"
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/api/option"
	"pkg.para.party/certdx/pkg/config"
)

type AcmeExternalAccount struct {
	HmacEncoded string `json:"hmac_encoded"`
	KeyId       string `json:"key_id"`
}

func CreateExternalAccountKeyRequest(config config.ACMEConfig) (AcmeExternalAccount, error) {
	credential, err := json.Marshal(config.GoogleCloudInfo.Credential)

	ctx := context.Background()
	c, err := publicca.NewPublicCertificateAuthorityClient(ctx, option.WithCredentialsJSON(credential))
	if err != nil {
		return AcmeExternalAccount{}, err
	}
	defer c.Close()

	req := &publiccapb.CreateExternalAccountKeyRequest{
		Parent:             fmt.Sprintf("projects/%s/locations/global", config.GoogleCloudInfo.Project),
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
