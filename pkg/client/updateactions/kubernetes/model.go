package kubernetes

// certDxDomainAnnotation marks which domains a TLS secret expects, and is
// matched against each certificate's configured domain set.
const certDxDomainAnnotation = "party.para.certdx/domains"
