package txtrecord

import "strings"

// version is the only record version RFC 8461 defines, the same as the
// policy file's.
const version = "STSv1"

// ID extracts the policy id from the _mta-sts.<domain> TXT records
// (RFC 8461 §3.1). Records that do not begin with "v=STSv1;" are discarded;
// exactly one must remain, and it must match the sts-text-record grammar.
// Otherwise the domain has no available policy.
func ID(records []string) (string, bool) {
	var sts []string
	for _, rec := range records {
		if rest, ok := strings.CutPrefix(rec, "v="+version); ok && strings.HasPrefix(strings.TrimLeft(rest, " \t"), ";") {
			sts = append(sts, rec)
		}
	}
	if len(sts) != 1 {
		return "", false
	}
	return parseSTSTextRecord(sts[0])
}

// parseSTSTextRecord validates a single TXT string against the RFC 8461 §3.1
// grammar and returns its policy id:
//
//	sts-text-record = sts-version 1*(sts-field-delim sts-field) [sts-field-delim]
//	sts-version     = %s"v=STSv1"
//	sts-field-delim = *WSP ";" *WSP
//	sts-field       = sts-id / sts-extension   ; sts-id required
//	sts-id          = %s"id=" 1*32(ALPHA / DIGIT)
//	sts-extension   = sts-ext-name "=" sts-ext-value
//	sts-ext-name    = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")
//	sts-ext-value   = 1*(%x21-3A / %x3C / %x3E-7E)
//
// The record must lead with the exact "v=STSv1" token, every field must match
// the grammar, and an "id=" field must be present. Whitespace is permitted only
// around the ";" delimiters. Unrecognized extension fields are ignored, and so
// is every repeat of a field after its first (RFC 8461 §3.2): a later "v=" or
// "id=" changes nothing. Any deviation yields ok=false so the caller treats the
// record as absent rather than discovering a policy off a malformed record.
func parseSTSTextRecord(rec string) (id string, ok bool) {
	s, found := strings.CutPrefix(rec, "v="+version)
	if !found {
		return "", false
	}
	sawID := false
	for s != "" {
		s = strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(s, ";") {
			return "", false
		}
		s = strings.TrimLeft(s[1:], " \t")
		if s == "" {
			break // the optional trailing delimiter
		}
		end := strings.IndexAny(s, " \t;")
		if end < 0 {
			end = len(s)
		}
		name, value, _ := strings.Cut(s[:end], "=")
		s = s[end:]
		if !validExtName(name) || !validExtValue(value) {
			return "", false
		}
		if name == "id" && !sawID {
			if !validSTSID(value) {
				return "", false
			}
			id, sawID = value, true
		}
	}
	return id, sawID
}

// validExtName reports whether s is an sts-ext-name: a letter or digit, then
// up to 31 letters, digits, "_", "-" or ".".
func validExtName(s string) bool {
	if s == "" || len(s) > 32 || !isAlnum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// validExtValue reports whether s is an sts-ext-value: one or more visible
// US-ASCII characters other than "=" and ";".
func validExtValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '=' || c == ';' {
			return false
		}
	}
	return true
}

// validSTSID reports whether s satisfies the sts-id value grammar
// 1*32(ALPHA / DIGIT): between 1 and 32 characters, each an ASCII letter or
// digit.
func validSTSID(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

// isAlnum reports whether c is ALPHA / DIGIT (RFC 5234).
func isAlnum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
