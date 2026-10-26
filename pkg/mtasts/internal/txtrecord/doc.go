// Package txtrecord reads the _mta-sts TXT record a Policy Domain publishes
// (RFC 8461 §3.1): it picks the one record that begins "v=STSv1;", checks it
// against the sts-text-record grammar and returns its policy id.
package txtrecord
