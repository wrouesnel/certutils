package certutils

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

var extKeyUsageFromOID = map[string]x509.ExtKeyUsage{}
var extKeyUsageToOID = map[x509.ExtKeyUsage]asn1.ObjectIdentifier{}

var strToKeyUsage = map[string]x509.KeyUsage{}
var knownUsages = []string{}

var strToExtKeyUsage = map[string]x509.ExtKeyUsage{}
var knownExtUsages = []string{}

func init() {
	extKeyUsageToOID[x509.ExtKeyUsageAny] = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	extKeyUsageToOID[x509.ExtKeyUsageServerAuth] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	extKeyUsageToOID[x509.ExtKeyUsageClientAuth] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	extKeyUsageToOID[x509.ExtKeyUsageCodeSigning] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	extKeyUsageToOID[x509.ExtKeyUsageEmailProtection] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	extKeyUsageToOID[x509.ExtKeyUsageIPSECEndSystem] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	extKeyUsageToOID[x509.ExtKeyUsageIPSECTunnel] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	extKeyUsageToOID[x509.ExtKeyUsageIPSECUser] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	extKeyUsageToOID[x509.ExtKeyUsageTimeStamping] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	extKeyUsageToOID[x509.ExtKeyUsageOCSPSigning] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	extKeyUsageToOID[x509.ExtKeyUsageMicrosoftServerGatedCrypto] = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	extKeyUsageToOID[x509.ExtKeyUsageNetscapeServerGatedCrypto] = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	extKeyUsageToOID[x509.ExtKeyUsageMicrosoftCommercialCodeSigning] = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	extKeyUsageToOID[x509.ExtKeyUsageMicrosoftKernelCodeSigning] = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}

	strToKeyUsage["DigitalSignature"] = x509.KeyUsageDigitalSignature
	strToKeyUsage["ContentCommitment"] = x509.KeyUsageContentCommitment
	strToKeyUsage["KeyEncipherment"] = x509.KeyUsageKeyEncipherment
	strToKeyUsage["DataEncipherment"] = x509.KeyUsageDataEncipherment
	strToKeyUsage["KeyAgreement"] = x509.KeyUsageKeyAgreement
	strToKeyUsage["CertSign"] = x509.KeyUsageCertSign
	strToKeyUsage["CRLSign"] = x509.KeyUsageCRLSign
	strToKeyUsage["EncipherOnly"] = x509.KeyUsageEncipherOnly
	strToKeyUsage["DecipherOnly"] = x509.KeyUsageDecipherOnly

	knownUsages = []string{
		"DigitalSignature",
		"ContentCommitment",
		"KeyEncipherment",
		"DataEncipherment",
		"KeyAgreement",
		"CertSign",
		"CRLSign",
		"EncipherOnly",
		"DecipherOnly",
	}

	strToExtKeyUsage["Any"] = x509.ExtKeyUsageAny
	strToExtKeyUsage["ServerAuth"] = x509.ExtKeyUsageServerAuth
	strToExtKeyUsage["ClientAuth"] = x509.ExtKeyUsageClientAuth
	strToExtKeyUsage["CodeSigning"] = x509.ExtKeyUsageCodeSigning
	strToExtKeyUsage["EmailProtection"] = x509.ExtKeyUsageEmailProtection
	strToExtKeyUsage["IPSECEndSystem"] = x509.ExtKeyUsageIPSECEndSystem
	strToExtKeyUsage["IPSECTunnel"] = x509.ExtKeyUsageIPSECTunnel
	strToExtKeyUsage["IPSECUser"] = x509.ExtKeyUsageIPSECUser
	strToExtKeyUsage["TimeStamping"] = x509.ExtKeyUsageTimeStamping
	strToExtKeyUsage["OCSPSigning"] = x509.ExtKeyUsageOCSPSigning
	strToExtKeyUsage["MicrosoftServerGatedCrypto"] = x509.ExtKeyUsageMicrosoftServerGatedCrypto
	strToExtKeyUsage["NetscapeServerGatedCrypto"] = x509.ExtKeyUsageNetscapeServerGatedCrypto
	strToExtKeyUsage["MicrosoftCommercialCodeSigning"] = x509.ExtKeyUsageMicrosoftCommercialCodeSigning
	strToExtKeyUsage["MicrosoftKernelCodeSigning"] = x509.ExtKeyUsageMicrosoftKernelCodeSigning

	knownExtUsages = []string{
		"Any",
		"ServerAuth",
		"ClientAuth",
		"CodeSigning",
		"EmailProtection",
		"IPSECEndSystem",
		"IPSECTunnel",
		"IPSECUser",
		"TimeStamping",
		"OCSPSigning",
		"MicrosoftServerGatedCrypto",
		"NetscapeServerGatedCrypto",
		"MicrosoftCommercialCodeSigning",
		"MicrosoftKernelCodeSigning",
	}

	// Setup the lower case lookup tables
	for _, value := range ListKeyUsage() {
		strToKeyUsage[strings.ToLower(value)] = strToKeyUsage[value]
	}

	for _, value := range ListExtKeyUsage() {
		strToExtKeyUsage[strings.ToLower(value)] = strToExtKeyUsage[value]
	}
}

type X509KeyUsage struct {
	x509.KeyUsage
}

func (x *X509KeyUsage) UnmarshalText(text []byte) (err error) {
	s := strings.TrimSpace(string(text))
	var v x509.KeyUsage
	v, err = ParseKeyUsage(s)
	x.KeyUsage = v
	return
}

type X509ExtKeyUsage struct {
	x509.ExtKeyUsage
}

func (x *X509ExtKeyUsage) UnmarshalText(text []byte) (err error) {
	s := strings.TrimSpace(string(text))
	var v x509.ExtKeyUsage
	v, err = ParseExtKeyUsage(s)
	x.ExtKeyUsage = v
	return
}

// ParseKeyUsage parses a string representation of extended key usage to the type.
func ParseKeyUsage(s string) (x509.KeyUsage, error) {
	usage, found := strToKeyUsage[s]
	if !found {
		return -1, fmt.Errorf("unknown key usage: %s", s)
	}
	return usage, nil
}

// ListExtKeyUsage outputs the list of known extended key usages as strings
func ListKeyUsage() []string {
	return knownUsages[:]
}

// ParseExtKeyUsage parses a string representation of extended key usage to the type.
func ParseExtKeyUsage(s string) (x509.ExtKeyUsage, error) {
	usage, found := strToExtKeyUsage[s]
	if !found {
		return -1, fmt.Errorf("unknown key usage: %s", s)
	}
	return usage, nil
}

// ListExtKeyUsage outputs the list of known extended key usages as strings
func ListExtKeyUsage() []string {
	return knownExtUsages[:]
}

// ExtKeyUsageToOid is a helper to convert Golang x509 ExtKeyUsages to OIDs
func ExtKeyUsageToOid(usage x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, found bool) {
	oid, found = extKeyUsageToOID[usage]
	return
}

// OIDToExtKeyUsage converts an asn1.ObjectIdentifier to a Golang x509.ExtKeyUsage type
func OIDToExtKeyUsage(oid asn1.ObjectIdentifier) (usage x509.ExtKeyUsage, found bool) {
	usage, found = extKeyUsageFromOID[oid.String()]
	return
}
