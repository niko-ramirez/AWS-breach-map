package authorization

import (
	"testing"
)

// =============================================================================
// checkKeyPolicyForPrincipal TESTS
// =============================================================================

func TestCheckKeyPolicyForPrincipal(t *testing.T) {
	tests := []struct {
		name         string
		policyJSON   *string
		principalARN string
		want         bool
		wantErr      bool
	}{
		{
			name: "principal allowed with kms:Decrypt",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         true,
			wantErr:      false,
		},
		{
			name: "wildcard principal allows any role",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "*"},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/AnyRole",
			want:         true,
			wantErr:      false,
		},
		{
			name: "kms:GenerateDataKey also grants access",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "kms:GenerateDataKey",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         true,
			wantErr:      false,
		},
		{
			name: "kms:* wildcard action",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "kms:*",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         true,
			wantErr:      false,
		},
		{
			name: "principal in array",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": [
						"arn:aws:iam::111111111111:root",
						"arn:aws:iam::123456789012:role/MyRole"
					]},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         true,
			wantErr:      false,
		},
		{
			name: "principal not in policy",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/OtherRole"},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         false,
			wantErr:      false,
		},
		{
			name: "deny effect not matched",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Deny",
					"Principal": {"AWS": "*"},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         false,
			wantErr:      false,
		},
		{
			name: "non-decrypt action not matched",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "kms:ListKeys",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         false,
			wantErr:      false,
		},
		{
			name:         "nil policy",
			policyJSON:   nil,
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         false,
			wantErr:      false,
		},
		{
			name:         "empty policy string",
			policyJSON:   strPtr(""),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         false,
			wantErr:      false,
		},
		{
			name:         "invalid JSON",
			policyJSON:   strPtr("not valid json"),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         false,
			wantErr:      true,
		},
		{
			name: "kms:CreateGrant action allows access",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "kms:CreateGrant",
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         true,
			wantErr:      false,
		},
		{
			name: "multiple actions in array",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": ["kms:DescribeKey", "kms:Encrypt", "kms:Decrypt"],
					"Resource": "*"
				}]
			}`),
			principalARN: "arn:aws:iam::123456789012:role/MyRole",
			want:         true,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkKeyPolicyForPrincipal(tt.policyJSON, tt.principalARN)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkKeyPolicyForPrincipal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("checkKeyPolicyForPrincipal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// parseKeyPolicy TESTS
// =============================================================================

func TestParseKeyPolicy(t *testing.T) {
	tests := []struct {
		name              string
		keyARN            string
		policyJSON        *string
		wantWildcard      bool
		wantPrincipalARN  string
		wantHasPrincipal  bool
		wantHasDecrypt    bool
		wantErr           bool
	}{
		{
			name:   "policy with wildcard principal",
			keyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "*"},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			wantWildcard:   true,
			wantHasDecrypt: true,
			wantErr:        false,
		},
		{
			name:   "policy with specific principal",
			keyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			wantWildcard:     false,
			wantPrincipalARN: "arn:aws:iam::123456789012:role/MyRole",
			wantHasPrincipal: true,
			wantHasDecrypt:   true,
			wantErr:          false,
		},
		{
			name:   "policy with multiple principals in array",
			keyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			policyJSON: strPtr(`{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": [
						"arn:aws:iam::123456789012:role/RoleA",
						"arn:aws:iam::123456789012:role/RoleB"
					]},
					"Action": "kms:Decrypt",
					"Resource": "*"
				}]
			}`),
			wantWildcard:     false,
			wantPrincipalARN: "arn:aws:iam::123456789012:role/RoleA",
			wantHasPrincipal: true,
			wantHasDecrypt:   true,
			wantErr:          false,
		},
		{
			name:             "nil policy",
			keyARN:           "arn:aws:kms:us-east-1:123456789012:key/test-key",
			policyJSON:       nil,
			wantWildcard:     false,
			wantHasPrincipal: false,
			wantHasDecrypt:   false,
			wantErr:          false,
		},
		{
			name:             "empty policy",
			keyARN:           "arn:aws:kms:us-east-1:123456789012:key/test-key",
			policyJSON:       strPtr(""),
			wantWildcard:     false,
			wantHasPrincipal: false,
			wantHasDecrypt:   false,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache before each test
			defaultVerifier.parsedKeyPolicyCache.Delete(tt.keyARN)

			parsed, err := defaultVerifier.parseKeyPolicy(tt.keyARN, tt.policyJSON)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if parsed.allowsWildcard != tt.wantWildcard {
				t.Errorf("parseKeyPolicy() allowsWildcard = %v, want %v", parsed.allowsWildcard, tt.wantWildcard)
			}

			if tt.wantHasPrincipal {
				if _, ok := parsed.allowedPrincipals[tt.wantPrincipalARN]; !ok {
					t.Errorf("parseKeyPolicy() missing principal %s", tt.wantPrincipalARN)
				}
			}

			// Verify caching works
			cached, ok := defaultVerifier.parsedKeyPolicyCache.Load(tt.keyARN)
			if !ok {
				t.Error("parseKeyPolicy() result not cached")
			}
			cachedPolicy := cached.(*parsedKeyPolicy)
			if cachedPolicy.allowsWildcard != tt.wantWildcard {
				t.Error("parseKeyPolicy() cached value mismatch")
			}
		})
	}
}

// =============================================================================
// normalizeToListInternal TESTS
// =============================================================================

func TestNormalizeToListInternal(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  []string
	}{
		{
			name:  "string value",
			value: "kms:Decrypt",
			want:  []string{"kms:Decrypt"},
		},
		{
			name:  "string slice",
			value: []string{"kms:Decrypt", "kms:Encrypt"},
			want:  []string{"kms:Decrypt", "kms:Encrypt"},
		},
		{
			name:  "interface slice",
			value: []interface{}{"kms:Decrypt", "kms:Encrypt"},
			want:  []string{"kms:Decrypt", "kms:Encrypt"},
		},
		{
			name:  "interface slice with non-strings",
			value: []interface{}{"kms:Decrypt", 123, "kms:Encrypt"},
			want:  []string{"kms:Decrypt", "kms:Encrypt"},
		},
		{
			name:  "nil value",
			value: nil,
			want:  []string{},
		},
		{
			name:  "integer returns empty",
			value: 42,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeToListInternal(tt.value)
			if !stringSlicesEqual(got, tt.want) {
				t.Errorf("normalizeToListInternal(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// =============================================================================
// isThrottlingError TESTS
// =============================================================================

func TestIsThrottlingError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "throttling error",
			err:  &testError{msg: "Throttling: Rate exceeded"},
			want: true,
		},
		{
			name: "rate exceeded error",
			err:  &testError{msg: "Rate exceeded for API call"},
			want: true,
		},
		{
			name: "429 error",
			err:  &testError{msg: "HTTP 429 Too Many Requests"},
			want: true,
		},
		{
			name: "TooManyRequests error",
			err:  &testError{msg: "TooManyRequests: slow down"},
			want: true,
		},
		{
			name: "rate limit error",
			err:  &testError{msg: "rate limit exceeded"},
			want: true,
		},
		{
			name: "access denied error",
			err:  &testError{msg: "AccessDenied: not allowed"},
			want: false,
		},
		{
			name: "generic error",
			err:  &testError{msg: "something went wrong"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isThrottlingError(tt.err)
			if got != tt.want {
				t.Errorf("isThrottlingError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS
// =============================================================================

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func strPtr(s string) *string {
	return &s
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

