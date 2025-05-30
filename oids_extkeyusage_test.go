package certutils

import (
	"crypto/x509"
	. "gopkg.in/check.v1"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type OidSuite struct {
}

var _ = Suite(&OidSuite{})

func (s *OidSuite) TestCertSpecificationUnmarshal(c *C) {
	var err error
	var a X509KeyUsage
	err = a.UnmarshalText([]byte("digitalsignature"))
	c.Assert(err, IsNil)
	c.Assert(a.KeyUsage, Equals, x509.KeyUsageDigitalSignature)

	var b X509ExtKeyUsage
	err = b.UnmarshalText([]byte("any"))
	c.Assert(err, IsNil)
	c.Assert(b.ExtKeyUsage, Equals, x509.ExtKeyUsageAny)
}
