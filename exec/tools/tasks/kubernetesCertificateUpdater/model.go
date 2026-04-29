package kubernetesCertificateUpdater

import "time"

type k8sCertsUpdateCmd struct {
	k8sConfig    string
	certdxConfig string
}

const (
	certDxDomainAnnotation = "party.para.certdx/domains"

	// waitDeadline bounds the total wait for all watched secrets to receive
	// their first certificate update from the certdx daemon.
	waitDeadline = 10 * time.Minute
)
