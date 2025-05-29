package certutils

import "strings"

// CommonNameToFileName converts an FQDN into a more unambiguous form for representation
// as a filename.
func CommonNameToFileName(cn string) string {
	outstr := cn
	outstr = strings.ReplaceAll(outstr, ".", "_")
	outstr = strings.ReplaceAll(outstr, " ", "")
	outstr = strings.ReplaceAll(outstr, "*", "STAR")
	return outstr
}
