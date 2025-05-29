package certutils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/pkg/errors"
)

var ErrCouldParsePemCertificateBytes = errors.New("Could not parse bytes as PEM certificate")
var ErrUnknownTypeForKey = errors.New("unknown type for encoding key")

const (
	// CertificateBlockType is a possible value for pem.Block.Type.
	CertificateBlockType        = "CERTIFICATE"
	RSAKeyBlockType             = "RSA PRIVATE KEY"
	ECKeyBlockType              = "EC PRIVATE KEY"
	CertificateRequestBlockType = "CERTIFICATE REQUEST"
)

// LoadCertificatesFromPem will read 1 or more PEM encoded x509 certificates
func LoadCertificatesFromPem(pemCerts []byte) ([]*x509.Certificate, error) {
	idx := 0
	certs := make([]*x509.Certificate, 0)
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			idx++
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return certs, errors.Wrapf(ErrCouldParsePemCertificateBytes, "error on block %v", idx)
		}

		certs = append(certs, cert)
		idx++
	}
	return certs, nil
}

// LoadPrivateKeysFromPem will read 1 or more PEM encoded private keys
func LoadPrivateKeysFromPem(pemKeys []byte) ([]interface{}, error) {
	idx := 0
	keys := make([]interface{}, 0)
	for len(pemKeys) > 0 {
		var block *pem.Block
		block, pemKeys = pem.Decode(pemKeys)
		if block == nil {
			break
		}

		var key interface{}
		var err error
		switch block.Type {
		case RSAKeyBlockType:
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case ECKeyBlockType:
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			idx++
			continue
		}

		if err != nil {
			return keys, errors.Wrapf(ErrCouldParsePemCertificateBytes, "error on block %v", idx)
		}

		keys = append(keys, key)
		idx++
	}
	return keys, nil
}

// pemBlockForKey returns a marshaled private key
// according to its type.
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: RSAKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Panicln("Unable to marshal ECDSA private key:", err)
		}
		return &pem.Block{Type: ECKeyBlockType, Bytes: b}
	default:
		return nil
	}
}

// EncodeCertificates returns the PEM-encoded byte array that represents by the specified certs.
// https://github.com/kubernetes/client-go/blob/master/util/cert/pem.go
func EncodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: CertificateBlockType, Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}

// EncodeKeys returns the PEM-encoded byte array that represents the specified key types
func EncodeKeys(keys ...interface{}) ([]byte, error) {
	b := bytes.NewBuffer(nil)
	for _, key := range keys {
		blockType := pemBlockForKey(key)
		if blockType == nil {
			return nil, ErrUnknownTypeForKey
		}
		keyBytes := pem.EncodeToMemory(blockType)
		if _, err := b.Write(keyBytes); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

// EncodeCertificates returns the PEM-encoded byte array that represents by the specified certs.
// https://github.com/kubernetes/client-go/blob/master/util/cert/pem.go
func EncodeRequest(csrs ...*x509.CertificateRequest) ([]byte, error) {
	b := bytes.Buffer{}
	for _, csr := range csrs {
		if err := pem.Encode(&b, &pem.Block{Type: CertificateRequestBlockType, Bytes: csr.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}
