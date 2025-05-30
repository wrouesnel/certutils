package certutils

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	extasn1 "github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

// 25 years (- 1 hour)
const CACertificateMaxDuration = ((time.Hour * 8760) * 25) - (2 * time.Hour)

// 398 days (- 1 second)
const CertificateMaxDuration = (time.Hour * 24 * 398) - (2 * time.Hour)

// CertificateNotBefore generates a sensible not-before value (this value will be two hours prior to the
// current time, which provides a window for systems using daylight savings badly).
func CertificateNotBefore() time.Time {
	return time.Now().Add(-2 * time.Hour)
}

// CertificateNotAfter generates a sensible not-after value - specifically, if time.Duration
// is zero, then it will set it to the accepted max duration of 398 days (- 2 hours).
// It also optionally takes a list of authority certificates - if set, the returned time
// will be constrained to not exceed the earliest expiry.
func CertificateNotAfter(duration time.Duration, authorities ...*x509.Certificate) time.Time {
	if duration == 0 {
		duration = CertificateMaxDuration
	}

	proposedTime := time.Now().Add(duration)

	for _, authority := range authorities {
		if proposedTime.After(authority.NotAfter) {
			proposedTime = authority.NotAfter
		}
	}

	return proposedTime
}

// CACertificateNotAfter is the same as CertificateNotAfter but follows the Microsoft Root
// trust program guideline (no more then 25 years).
func CACertificateNotAfter(duration time.Duration) time.Time {
	if duration == 0 {
		duration = CACertificateMaxDuration
	}
	return time.Now().Add(duration)
}

// GenerateCSR generates a certificate for the given hosts.
// Parameters are common template parameters, key is the private key associated with the certificate.
func GenerateCSR(subject pkix.Name, parameters CSRParameters, key interface{}, hosts ...string) (*x509.CertificateRequest, error) {
	// Put the correct
	basicConstraints, _ := extensions.BasicConstraints{
		Critical:   true,
		IsCA:       parameters.IsCA,
		MaxPathLen: parameters.MaxPathLen,
	}.Marshal()

	keyUsage, _ := extensions.KeyUsage{
		Critical: true,
		Value:    parameters.KeyUsage,
	}.Marshal()

	extraExtensions := []pkix.Extension{basicConstraints, keyUsage}

	if len(parameters.ExtKeyUsage) > 0 {
		oids := make([]asn1.ObjectIdentifier, 0, len(parameters.ExtKeyUsage))
		for _, usage := range parameters.ExtKeyUsage {
			oid, found := ExtKeyUsageToOid(usage)
			if !found {
				continue
			}
			oids = append(oids, oid)
		}
		extUsages, _ := extensions.ExtendedKeyUsage{
			Critical: false,
			OIDs:     oids,
		}.Marshal()
		extraExtensions = append(extraExtensions, extUsages)
	}

	if parameters.CertificateTemplate != "" {
		certificateTemplate, _ := CertificateTypeExtension{
			Name: parameters.CertificateTemplate,
		}.Marshal()
		extraExtensions = append(extraExtensions, certificateTemplate)
	}

	csr := x509.CertificateRequest{
		Subject:         subject,
		ExtraExtensions: extraExtensions,
	}

	if len(hosts) > 0 && csr.Subject.CommonName == "" {
		csr.Subject.CommonName = hosts[0]
	}

	emails := []string{}
	for _, host := range hosts {
		if strings.Contains(host, "@") {
			emails = append(emails, host)
		} else if ip := net.ParseIP(host); ip != nil {
			// IP SAN
			csr.IPAddresses = append(csr.IPAddresses, ip)
		} else if strings.Contains(host, "://") {
			u, _ := url.Parse(host)
			csr.URIs = append(csr.URIs, u)
		} else {
			// Regular DNS SAN (the most common
			csr.DNSNames = append(csr.DNSNames, host)
		}
	}

	if len(emails) > 0 {
		csr.EmailAddresses = append(csr.EmailAddresses, emails...)
	}
	csr.PublicKey = PublicKey(key)

	signedCSRBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, key)
	if err != nil {
		return nil, errors.Join(errors.New("error creating certificate request"), err)
	}

	signedCSR, err := x509.ParseCertificateRequest(signedCSRBytes)
	if err != nil {
		return nil, errors.Join(errors.New("error parsing certificate request"), err)
	}

	return signedCSR, nil
}

// CSRParameters sets parameters for generating a CSR
type CSRParameters struct {
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	IsCA        bool
	MaxPathLen  int
	// This parameter is used by some CAs (i.e. ADCS) to determine which template
	// to apply. So we should support it.
	CertificateTemplate string
}

// SigningParameters sets parameters determined by the authority signing
type SigningParameters struct {
	SerialNumber int64
	NotBefore    time.Time
	NotAfter     time.Time
}

// CsrToCertificateTemplate converts a certificate signing request to a certificate template ready to be signed.
func CsrToCertificateTemplate(csr *x509.CertificateRequest, parameters SigningParameters) *x509.Certificate {
	certificate := &x509.Certificate{
		SerialNumber:       big.NewInt(parameters.SerialNumber),
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Subject:            csr.Subject,
		ExtraExtensions:    csr.Extensions,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
		NotBefore:          parameters.NotBefore,
		NotAfter:           parameters.NotAfter,
		ExtKeyUsage:        []x509.ExtKeyUsage{},
	}

	// We need to parse the extensions to regenerate x509.Certificate objects
	// so signing works properly.
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(extasn1.OIDBasicConstraints) {
			r := extensions.BasicConstraints{}
			if err := r.Unmarshal(ext); err != nil {
				continue
			}
			certificate.IsCA = r.IsCA
			certificate.MaxPathLen = r.MaxPathLen
		} else if ext.Id.Equal(extasn1.OIDKeyUsage) {
			r := extensions.KeyUsage{}
			r.Unmarshal(ext)
			if err := r.Unmarshal(ext); err != nil {
				continue
			}
			certificate.KeyUsage = r.Value
		} else if ext.Id.Equal(extasn1.OIDExtendedKeyUsage) {
			r := extensions.ExtendedKeyUsage{}
			r.Unmarshal(ext)
			for _, oid := range r.OIDs {
				usage, found := OIDToExtKeyUsage(oid)
				if found {
					certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, usage)
				}
			}
		}
	}

	return certificate
}

// SignCertificate signs a CSR for use as a TLS server certificate
func SignCertificate(csr *x509.CertificateRequest, authority *x509.Certificate, authorityKey interface{}, parameters SigningParameters) (*x509.Certificate, error) {
	certificate := CsrToCertificateTemplate(csr, parameters)

	if authority == nil {
		authority = certificate
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, certificate, authority, certificate.PublicKey, authorityKey)
	if err != nil {
		return nil, err
	}

	signedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	return signedCertificate, nil
}

// RequestTLSCertificate generates and signs a certificate for the given hostname using defaults derived from the
// CA certificate. The returns *tls.Certificate contains the private key of the generated certificate.
func RequestTLSCertificateWithUsages(authority *x509.Certificate, authorityKey interface{},
	parameters SigningParameters, keyType PrivateKeyType, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage, isCA bool, hosts ...string) *tls.Certificate {
	if len(hosts) == 0 {
		return nil
	}
	// Use subject data from the authority certificate
	subject := authority.Subject
	subject.Names = nil
	subject.ExtraNames = nil
	// Blank out the certificate specific fields
	subject.SerialNumber = ""
	subject.CommonName = hosts[0]

	key, err := GeneratePrivateKey(keyType)
	if err != nil {
		return nil
	}

	// Request the CSR
	csrParams := CSRParameters{
		KeyUsage:    usage,
		ExtKeyUsage: extUsage,
		IsCA:        isCA,
	}
	csr, err := GenerateCSR(subject, csrParams, key, hosts...)
	if err != nil {
		return nil
	}

	// Sign the CSR
	certificate, err := SignCertificate(csr, authority, authorityKey, parameters)
	if err != nil {
		return nil
	}
	return &tls.Certificate{
		Certificate: [][]byte{certificate.Raw, authority.Raw},
		PrivateKey:  key,
		Leaf:        certificate,
	}
}

// RequestTLSCertificate generates and signs a certificate for the given hostname using defaults derived from the
// CA certificate. The returns *tls.Certificate contains the private key of the generated certificate. This will be a
// server certificate suitable for typical host verification.
func RequestTLSCertificate(authority *x509.Certificate, authorityKey interface{},
	parameters SigningParameters, keyType PrivateKeyType, hosts ...string) *tls.Certificate {

	if len(hosts) == 0 {
		return nil
	}

	return RequestTLSCertificateWithUsages(authority, authorityKey, parameters, keyType, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, hosts...)
}
