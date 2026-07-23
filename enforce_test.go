package mtasts

import (
	"errors"
	"testing"
)

func TestEvaluate(t *testing.T) {
	enforce := &Policy{Mode: ModeEnforce, MX: []string{"mail.example.com", "*.mx.example.com"}, MaxAge: 86400}
	testingPol := &Policy{Mode: ModeTesting, MX: []string{"mail.example.com"}, MaxAge: 86400}
	nonePol := &Policy{Mode: ModeNone, MaxAge: 86400}

	cases := []struct {
		name    string
		in      EvalInput
		wantErr bool
	}{
		{
			name:    "enforce + STARTTLS + valid cert => allow",
			in:      EvalInput{Policy: enforce, Mode: ModeEnforce, MXHost: "mail.example.com", STARTTLS: true, CertValid: true},
			wantErr: false,
		},
		{
			name:    "enforce + wildcard-named MX + valid cert => allow",
			in:      EvalInput{Policy: enforce, Mode: ModeEnforce, MXHost: "a.mx.example.com", STARTTLS: true, CertValid: true},
			wantErr: false,
		},
		{
			name:    "enforce + cleartext (no STARTTLS) => defer",
			in:      EvalInput{Policy: enforce, Mode: ModeEnforce, MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: true,
		},
		{
			name:    "enforce + STARTTLS but invalid/mismatched cert => defer",
			in:      EvalInput{Policy: enforce, Mode: ModeEnforce, MXHost: "mail.example.com", STARTTLS: true, CertValid: false},
			wantErr: true,
		},
		{
			name:    "enforce + MX host not named by policy => defer",
			in:      EvalInput{Policy: enforce, Mode: ModeEnforce, MXHost: "sneaky.other.com", STARTTLS: true, CertValid: true},
			wantErr: true,
		},
		{
			name:    "testing + cleartext => allow (would-fail only)",
			in:      EvalInput{Policy: testingPol, Mode: ModeTesting, MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
		{
			name:    "none => allow",
			in:      EvalInput{Policy: nonePol, Mode: ModeNone, MXHost: "whatever.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
		{
			name:    "no policy => allow",
			in:      EvalInput{Policy: nil, Mode: "", MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
		{
			name:    "enforce downgraded to testing by caller => allow despite cleartext",
			in:      EvalInput{Policy: enforce, Mode: ModeTesting, MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(c.in)
			if c.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
			if c.wantErr {
				var ee *EnforceError
				if !errors.As(err, &ee) {
					t.Fatalf("expected *EnforceError, got %T", err)
				}
			}
		})
	}
}
