//go:generate go tool go-enum --lower
package certutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

type ErrPrivateKeyGeneration struct {
	Reason string
}

func (e ErrPrivateKeyGeneration) Error() string {
	return e.Reason
}

type ErrUnknownPrivateKey struct {
}

func (e ErrUnknownPrivateKey) Error() string {
	return "unknown private key type"
}

// PrivateKeyType is the list of allowable RSA bit lengths
// ENUM(rsa2048, rsa3076, rsa4096, ecp256, ecp384, ecp521)
type PrivateKeyType string

// PublicKey detects the type of key and returns its PublicKey.
func PublicKey(priv interface{}) interface{} {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case x509.Certificate:
		// For handling CSR requests
		return key.PublicKey
	default:
		return nil
	}
}

// GetPrivateKeyType returns the type of private key according to the known
// types in this package, or an error if it does not match.
func GetPrivateKeyType(priv interface{}) (PrivateKeyType, error) {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		switch key.N.BitLen() {
		case 2048:
			return PrivateKeyTypeRsa2048, nil
		case 3072:
			return PrivateKeyTypeRsa3076, nil
		case 4096:
			return PrivateKeyTypeRsa4096, nil
		default:
			return "", &ErrUnknownPrivateKey{}
		}
	case *ecdsa.PrivateKey:
		switch key.Curve.Params().Name {
		case elliptic.P256().Params().Name:
			return PrivateKeyTypeEcp256, nil
		case elliptic.P256().Params().Name:
			return PrivateKeyTypeEcp384, nil
		case elliptic.P256().Params().Name:
			return PrivateKeyTypeEcp521, nil
		default:
			return "", &ErrUnknownPrivateKey{}
		}
	default:
		return "", &ErrUnknownPrivateKey{}
	}
}

// GeneratePrivateKey generates a new secure private key based on the type requested.
func GeneratePrivateKey(keyType PrivateKeyType) (interface{}, error) {
	switch keyType {
	case PrivateKeyTypeRsa2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case PrivateKeyTypeRsa3076:
		return rsa.GenerateKey(rand.Reader, 3072)
	case PrivateKeyTypeRsa4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	// P224 curve is disabled because Red Hat disable it.
	case PrivateKeyTypeEcp256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case PrivateKeyTypeEcp384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case PrivateKeyTypeEcp521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, &ErrPrivateKeyGeneration{fmt.Sprintf("unknown key type: %s", keyType)}
	}
}
