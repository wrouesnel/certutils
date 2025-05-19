package certutils

import (
	"crypto/x509"
	"encoding/asn1"
)

var extKeyUsageFromOID = map[string]x509.ExtKeyUsage{}
var extKeyUsageToOID = map[x509.ExtKeyUsage]asn1.ObjectIdentifier{}

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
