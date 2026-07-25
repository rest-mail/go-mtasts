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
			in:      EvalInput{Policy: enforce, MXHost: "mail.example.com", STARTTLS: true, CertValid: true},
			wantErr: false,
		},
		{
			name:    "enforce + wildcard-named MX + valid cert => allow",
			in:      EvalInput{Policy: enforce, MXHost: "a.mx.example.com", STARTTLS: true, CertValid: true},
			wantErr: false,
		},
		{
			name:    "enforce + cleartext (no STARTTLS) => defer",
			in:      EvalInput{Policy: enforce, MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: true,
		},
		{
			name:    "enforce + STARTTLS but invalid/mismatched cert => defer",
			in:      EvalInput{Policy: enforce, MXHost: "mail.example.com", STARTTLS: true, CertValid: false},
			wantErr: true,
		},
		{
			name:    "enforce + MX host not named by policy => defer",
			in:      EvalInput{Policy: enforce, MXHost: "sneaky.other.com", STARTTLS: true, CertValid: true},
			wantErr: true,
		},
		{
			name:    "testing + cleartext => allow (would-fail only)",
			in:      EvalInput{Policy: testingPol, MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
		{
			name:    "none => allow",
			in:      EvalInput{Policy: nonePol, MXHost: "whatever.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
		{
			name:    "no policy => allow",
			in:      EvalInput{Policy: nil, MXHost: "mail.example.com", STARTTLS: false, CertValid: false},
			wantErr: false,
		},
		{
			name:    "enforce + explicit insecure downgrade => allow despite cleartext",
			in:      EvalInput{Policy: enforce, MXHost: "mail.example.com", STARTTLS: false, CertValid: false, AllowInsecureDowngrade: true},
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

// TestEvaluateGatesOnPolicyMode is the regression guard for issue #8: a caller
// that populates the discovered policy but does not separately restate its mode
// must still get enforcement. Enforcement is a property of Policy.Mode, so an
// "enforce" policy with a mismatching MX (or missing TLS) must FAIL CLOSED even
// when the caller supplies nothing beyond the policy itself.
func TestEvaluateGatesOnPolicyMode(t *testing.T) {
	enforce := &Policy{Mode: ModeEnforce, MX: []string{"mail.example.com"}, MaxAge: 86400}

	requireBlocked := func(t *testing.T, in EvalInput) {
		t.Helper()
		err := Evaluate(in)
		if err == nil {
			t.Fatalf("enforce policy must fail closed, got nil (fail-open)")
		}
		var ee *EnforceError
		if !errors.As(err, &ee) {
			t.Fatalf("expected *EnforceError, got %T", err)
		}
	}

	t.Run("mismatching MX with valid TLS", func(t *testing.T) {
		requireBlocked(t, EvalInput{
			Policy:    enforce,
			Domain:    "example.com",
			MXHost:    "sneaky.other.com",
			STARTTLS:  true,
			CertValid: true,
		})
	})
	t.Run("named MX but cleartext", func(t *testing.T) {
		requireBlocked(t, EvalInput{
			Policy:    enforce,
			Domain:    "example.com",
			MXHost:    "mail.example.com",
			STARTTLS:  false,
			CertValid: false,
		})
	})
}
