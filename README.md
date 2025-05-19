[![Test](https://github.com/wrouesnel/certutils/actions/workflows/test.yml/badge.svg)](https://github.com/wrouesnel/certutils/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/certutils/badge.svg?branch=main)](https://coveralls.io/github/wrouesnel/certutils?branch=main)
[![Go Reference](https://pkg.go.dev/badge/github.com/wrouesnel/certutils.svg)](https://pkg.go.dev/github.com/wrouesnel/certutils)
[![Go Report Card](https://goreportcard.com/badge/github.com/wrouesnel/certutils)](https://goreportcard.com/report/github.com/wrouesnel/certutils)

# certutils

This is an extracted library of common certificate functions which are useful
for implementing various bits of x509 certificate handling.

Notably it implements functions suitable for handling the basic CSR -> Certificate
flow in a way which sticks with a set of sane defaults, including parsing
certificate usages out of CSR requests.
