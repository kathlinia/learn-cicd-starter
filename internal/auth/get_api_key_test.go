package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
	}{
		{
			name:       "valid API key",
			authHeader: "ApiKey test-api-key-123",
			wantKey:    "test-api-key-123",
		},
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed authorization header",
			authHeader: "Bearer test-api-key-123",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("GetAPIKey() unexpected error: %v", err)
				}
				return
			}

			if err == nil || err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
