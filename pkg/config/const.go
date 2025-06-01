package config

const (
	HTTP_AUTH_TOKEN string = "token"
	HTTP_AUTH_MTLS  string = "mtls"
)

const (
	DnsProviderTypeCloudflare   string = "cloudflare"
	DnsProviderTypeTencentCloud string = "tencentcloud"

	HttpProviderTypeS3    string = "s3"
	HttpProviderTypeLocal string = "local"
)

const (
	ChallengeTypeDns01  string = "dns"
	ChallengeTypeHttp01 string = "http"
)

const (
	CLIENT_MODE_HTTP string = "http"
	CLIENT_MODE_GRPC string = "grpc"
)
