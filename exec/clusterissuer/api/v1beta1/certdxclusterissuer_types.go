/*
Copyright 2024 ParaParty.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CertDXClusterIssuerSpec defines the desired state of CertDXClusterIssuer
type CertDXClusterIssuerSpec struct {
	Url      string `json:"url,omitempty"`
	Token    string `json:"token,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// CertDXClusterIssuer is the Schema for the certdxclusterissuers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="reason",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].reason"
// +kubebuilder:printcolumn:name="message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
type CertDXClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertDXClusterIssuerSpec `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus   `json:"status,omitempty"`
}

func (vi *CertDXClusterIssuer) GetStatus() *v1alpha1.IssuerStatus {
	return &vi.Status
}

func (vi *CertDXClusterIssuer) GetIssuerTypeIdentifier() string {
	return "certdxclusterissuers.certdx.para.party"
}

//+kubebuilder:object:root=true

// CertDXClusterIssuerList contains a list of CertDXClusterIssuer
type CertDXClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertDXClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertDXClusterIssuer{}, &CertDXClusterIssuerList{})
}
