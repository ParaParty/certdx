package tools

type CertificateUpdater interface {
	InitCertificateUpdater() error
	InvokeCertificateUpdate() error
}
