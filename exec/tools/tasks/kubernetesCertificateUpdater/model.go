package kubernetesCertificateUpdater

type k8sCertsUpdateCmd struct {
	k8sConfig    *string
	certdxConfig *string
}

const certDxDomainAnnotation = "party.para.certdx/domains"
