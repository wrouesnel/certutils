package certutils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	goasn1 "encoding/asn1"
	"errors"
	"fmt"
	"github.com/paulgriffiths/pki/extensions"
)

var oidExtensionCertificateType goasn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 311, 20, 2}

type CertificateTypeExtension struct {
	Name string `asn1:"printable"`
}

// Marshal returns a pkix.Extension.
func (e CertificateTypeExtension) Marshal() (pkix.Extension, error) {
	if len(e.Name) == 0 {
		return pkix.Extension{}, errors.New("no certificate type specified")
	}

	der, err := asn1.Marshal(e.Name)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:    oidExtensionCertificateType,
		Value: der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *CertificateTypeExtension) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(oidExtensionCertificateType) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	if rest, err := asn1.Unmarshal(ext.Value, &e.Name); err != nil {
		return err
	} else if len(rest) > 0 {
		return extensions.ErrTrailingBytes
	}

	return nil
}
