package certutils

import (
	"crypto/tls"
	"github.com/spf13/afero"
	"io"
)

// LoadX509KeyPair implements tls.LoadX509KeyPair but accepts an afero filesystem override.
func LoadX509KeyPair(fs afero.Fs, certFile, keyFile string) (tls.Certificate, error) {
	certFileHandle, err := fs.Open(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer certFileHandle.Close()

	certPEMBlock, err := io.ReadAll(certFileHandle)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyFileHandle, err := fs.Open(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer keyFileHandle.Close()

	keyPEMBlock, err := io.ReadAll(keyFileHandle)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}
