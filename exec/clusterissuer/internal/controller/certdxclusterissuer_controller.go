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

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	controllers "github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"k8s.io/apimachinery/pkg/runtime"
	issuersv1beta1 "pkg.para.party/certdx/exec/clusterissuer/api/v1beta1"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	ctrl "sigs.k8s.io/controller-runtime"
	sigsClient "sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

var (
	signerLog = ctrl.Log.WithName("signer")
)

// CertDXClusterIssuerReconciler reconciles a CertDXClusterIssuer object
type CertDXClusterIssuerReconciler struct {
	Client           sigsClient.Client
	Scheme           *runtime.Scheme
	MaxRetryDuration time.Duration
}

//+kubebuilder:rbac:groups=certdx.para.party,resources=certdxclusterissuers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=certdx.para.party,resources=certdxclusterissuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=certdx.para.party,resources=certdxclusterissuers/finalizers,verbs=update
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=list
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=list,resourceNames=certdxclusterissuers.certdx.para.party

// SetupWithManager sets up the controller with the Manager.
func (r *CertDXClusterIssuerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	const fieldOwner = "certdx.para.party"

	if err := cmapi.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}

	if err := issuersv1beta1.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{},
		ClusterIssuerTypes: []issuerapi.Issuer{&issuersv1beta1.CertDXClusterIssuer{}},

		FieldOwner:       fieldOwner,
		MaxRetryDuration: r.MaxRetryDuration,

		Sign:  r.Sign,
		Check: r.Check,

		SetCAOnCertificateRequest: true,

		EventRecorder: mgr.GetEventRecorderFor(fieldOwner),
	}).SetupWithManager(ctx, mgr)
}

func (o *CertDXClusterIssuerReconciler) extractIssuerSpec(obj sigsClient.Object) (issuerSpec *issuersv1beta1.CertDXClusterIssuerSpec) {
	switch t := obj.(type) {
	case *issuersv1beta1.CertDXClusterIssuer:
		return &t.Spec
	}

	panic("Program Error: Unhandled issuer type")
}

func IssuerSpecToCertDXClientHttpServer(t *issuersv1beta1.CertDXClusterIssuerSpec) *client.CertDXHttpClient {

	opt := make([]client.CertDXHttpClientOption, 0)
	opt = append(opt, client.WithCertDXServerInfo(&config.ClientHttpServer{
		Url:   t.Url,
		Token: t.Token,
	}))

	if t.Insecure {
		opt = append(opt, client.WithCertDXInsecure())
	}

	return client.MakeCertDXHttpClient(opt...)
}

func (o *CertDXClusterIssuerReconciler) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObj issuerapi.Issuer) (signer.PEMBundle, error) {
	signerLog.Info("start processing request")

	issuerSpec := o.extractIssuerSpec(issuerObj)
	certDxClient := IssuerSpecToCertDXClientHttpServer(issuerSpec)

	_, _, csr, err := cr.GetRequest()
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("fail to get CertificateRequest: %v", err)
	}
	signerLog.Info("requesting cert", "cr", csr)

	csrBytes, _ := pem.Decode(csr)
	if csrBytes == nil {
		return signer.PEMBundle{}, fmt.Errorf("unable to decode CSR")
	}

	csrD, err := x509.ParseCertificateRequest(csrBytes.Bytes)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("unable to parse CSR: %v", err)
	}

	signerLog.Info("requesting certdx", "domains", csrD.DNSNames)
	resp, err := certDxClient.GetCertCtx(ctx, csrD.DNSNames)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	return signer.PEMBundle{
		ChainPEM: resp.FullChain,
		CAPEM:    resp.Key,
	}, nil
}

func (o *CertDXClusterIssuerReconciler) Check(ctx context.Context, issuerObj issuerapi.Issuer) error {
	return nil
}
