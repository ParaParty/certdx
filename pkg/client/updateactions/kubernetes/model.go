package kubernetes

import corev1 "k8s.io/api/core/v1"

// certDxDomainAnnotation marks which domains a TLS secret expects, and is
// matched against each certificate's configured domain set.
const certDxDomainAnnotation = "party.para.certdx/domains"

// tlsSecretFieldSelector restricts a secret list to kubernetes.io/tls
// secrets, the only type this action ever updates.
const tlsSecretFieldSelector = "type=" + string(corev1.SecretTypeTLS)
