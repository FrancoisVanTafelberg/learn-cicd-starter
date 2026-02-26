package auth

import (
	"fmt"
	"testing"
	"errors"
	"net/http"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name		string
		authValue	string
		wantKey		string
		wantErr		error
	}{
		{
			name:		"no autthorization header",
			wantErr:	ErrNoAuthHeaderIncluded,
		},
		{
			name:		"empty autthorization header",
			authValue:	"",
			wantErr:	ErrNoAuthHeaderIncluded,
		},
		{
			name:		"malformed - no token",
			authValue:	"ApiKey",
			wantErr:	errors.New("malformed authorization header"),
		},
		{
			name:		"malformed - wrong scheme",
			authValue:	"Bearer abc123",
			wantErr:	errors.New("malformed authorization header"),
		},
		{
			name:		"malformed - scheme case sensitive",
			authValue:	"apikey abc123",
			wantErr:	errors.New("malformed authorization header"),
		},
		{
			name:		"valid",
			authValue:	"ApiKey abc123",
			wantKey:	"abc123",
		},
		{
			name:		"valid - exta parts ignored",
			authValue:	"ApiKey abc123 extra",
			wantKey:	"abc123",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("%s", tc.name), func(t *testing.T) {
			h := make(http.Header)

			if tc.authValue != "" {
				h.Set("Authorization", tc.authValue)
			}

			gotKey, err := GetAPIKey(h)

			// Success case
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				if gotKey != tc.wantKey {
					t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
				}
				return
			}

			// Error cases
			if err == nil {
				t.Fatalf("expected error but got nil (for key=%q)", gotKey)
			}
			if gotKey != "" {
				t.Fatalf("expected empty key on error but got %q", gotKey)
			}

			// Err cases
			if errors.Is(tc.wantErr, ErrNoAuthHeaderIncluded) {
				if !errors.Is(err, ErrNoAuthHeaderIncluded) {
					t.Fatalf("expected ErrNoAuthHeaderIncluded but got %v", err)
				}
				return
			}

			// Malformed errors
			if err.Error() != tc.wantErr.Error() {
				t.Fatalf("expected error %q but got %v", tc.wantErr.Error(), err.Error())
			}
		})
	}
}

