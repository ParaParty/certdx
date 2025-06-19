package txcCertificateUpdater

import (
	txcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	txssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"pkg.para.party/certdx/pkg/types"
)

type ResourceTypeRegions struct {
	ResourceType string   `toml:"resourceType" json:"ResourceType,omitnil,omitempty" name:"resource_type"`
	Regions      []string `toml:"regions" json:"Regions,omitnil,omitempty" name:"regions"`
}

type ClientCertification struct {
	Name                 string                `toml:"name" json:"name,omitempty"`
	Domains              []string              `toml:"domains" json:"domains,omitempty"`
	ResourceTypes        []string              `toml:"resourceTypes" json:"resource_types"`
	ResourceTypesRegions []ResourceTypeRegions `toml:"resourceTypesRegions" json:"resource_types_regions"`

	certDxKey        types.DomainKey
	oldCertificateId string
}

func (r *ClientCertification) ToResourceTypesAndResourceTypesRegions() (resourceTypes []*string, resourceTypesRegions []*txssl.ResourceTypeRegions) {
	resourceTypes = make([]*string, 0)
	resourceTypesRegions = make([]*txssl.ResourceTypeRegions, 0)

	resourceTypes = txcommon.StringPtrs(r.ResourceTypes)
	for _, it := range r.ResourceTypesRegions {
		resourceTypesRegions = append(resourceTypesRegions, &txssl.ResourceTypeRegions{
			ResourceType: txcommon.StringPtr(it.ResourceType),
			Regions:      txcommon.StringPtrs(it.Regions),
		})
	}
	if len(resourceTypesRegions) == 0 {
		resourceTypesRegions = nil
	}

	return resourceTypes, resourceTypesRegions
}

type TencentCloudConfig struct {
	Authorization struct {
		SecretID  string `toml:"secretID" json:"secret_id,omitempty"`
		SecretKey string `toml:"secretKey" json:"secret_key,omitempty"`
	} `toml:"Authorization" json:"authorization,omitempty"`

	Certifications []ClientCertification `toml:"Certifications" json:"certifications,omitempty"`
}

type txcCertsUpdateCmd struct {
	confPath *string
}
