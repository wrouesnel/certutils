package certutils

import (
	. "gopkg.in/check.v1"
)

type ExtSuite struct {
}

var _ = Suite(&ExtSuite{})

func (s *ExtSuite) TestCertificateTemplateExtension(c *C) {
	var err error
	a := CertificateTypeExtension{Name: "WebServer"}

	ext, err := a.Marshal()
	c.Assert(err, IsNil)

	b := CertificateTypeExtension{}
	err = b.Unmarshal(ext)
	c.Assert(err, IsNil)
	c.Assert(b.Name, Equals, a.Name)
}
