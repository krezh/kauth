package cmd

import "testing"

func TestBuildToken(t *testing.T) {
	tests := []struct {
		name      string
		idToken   string
		sessionID string
		want      string
	}{
		{
			name:      "with session ID produces compound token",
			idToken:   "header.payload.sig",
			sessionID: "sess123",
			want:      "kauth_sess123.header.payload.sig",
		},
		{
			name:      "without session ID falls back to bare ID token",
			idToken:   "header.payload.sig",
			sessionID: "",
			want:      "header.payload.sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildToken(tt.idToken, tt.sessionID); got != tt.want {
				t.Errorf("buildToken(%q, %q) = %q, want %q", tt.idToken, tt.sessionID, got, tt.want)
			}
		})
	}
}
