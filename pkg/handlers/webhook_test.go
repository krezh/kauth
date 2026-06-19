package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/jwt"

	authnv1 "k8s.io/api/authentication/v1"
)

// fakeSessionGetter implements sessionGetter for webhook tests.
type fakeSessionGetter struct {
	session *v1alpha1.OAuthSession
	err     error
}

func (f *fakeSessionGetter) Get(_ context.Context, _ string) (*v1alpha1.OAuthSession, error) {
	return f.session, f.err
}

func activeSession(email string, groups []string) *v1alpha1.OAuthSession {
	return &v1alpha1.OAuthSession{
		Status: v1alpha1.OAuthSessionStatus{
			Phase:  v1alpha1.SessionActive,
			Email:  email,
			Groups: groups,
		},
	}
}

func revokedSession(email string) *v1alpha1.OAuthSession {
	return &v1alpha1.OAuthSession{
		Status: v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionRevoked,
			Email: email,
		},
	}
}

func newTestJWTManager(t *testing.T) *jwt.Manager {
	t.Helper()
	sigKey := make([]byte, 32)
	encKey := make([]byte, 32)
	m, err := jwt.NewManager(sigKey, encKey)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func postTokenReview(t *testing.T, h *WebhookHandler, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook/token-review", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.HandleTokenReview(rr, req)
	return rr
}

func decodeReview(t *testing.T, rr *httptest.ResponseRecorder) authnv1.TokenReview {
	t.Helper()
	var resp authnv1.TokenReview
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	return resp
}

func TestHandleTokenReview_Authentication(t *testing.T) {
	const email = "user@example.com"
	groups := []string{"devs", "admins"}

	jm := newTestJWTManager(t)

	validToken, err := jm.CreateWebhookToken("sess-abc", 24*60*60*1000000000) // 24h
	if err != nil {
		t.Fatalf("CreateWebhookToken: %v", err)
	}

	tests := []struct {
		name          string
		token         string
		session       sessionGetter
		wantAuthd     bool
		wantUsername  string
		wantGroupsLen int
	}{
		{
			name:          "valid token with active session",
			token:         validToken,
			session:       &fakeSessionGetter{session: activeSession(email, groups)},
			wantAuthd:     true,
			wantUsername:  email,
			wantGroupsLen: 2,
		},
		{
			name:      "valid token with revoked session",
			token:     validToken,
			session:   &fakeSessionGetter{session: revokedSession(email)},
			wantAuthd: false,
		},
		{
			name:      "valid token but session lookup fails",
			token:     validToken,
			session:   &fakeSessionGetter{err: fmt.Errorf("not found")},
			wantAuthd: false,
		},
		{
			name:      "garbage token is rejected",
			token:     "notavalidtoken",
			session:   &fakeSessionGetter{session: activeSession(email, groups)},
			wantAuthd: false,
		},
		{
			name:      "empty token is rejected",
			token:     "",
			session:   &fakeSessionGetter{session: activeSession(email, groups)},
			wantAuthd: false,
		},
		{
			name:      "old compound token format is rejected",
			token:     "kauth_sess123.header.payload.sig",
			session:   &fakeSessionGetter{session: activeSession(email, groups)},
			wantAuthd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &WebhookHandler{jwtManager: jm, sessionClient: tt.session}
			rr := postTokenReview(t, h, tt.token)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rr.Code)
			}

			resp := decodeReview(t, rr)
			if resp.Status.Authenticated != tt.wantAuthd {
				t.Errorf("authenticated = %v, want %v", resp.Status.Authenticated, tt.wantAuthd)
			}
			if resp.Kind != "TokenReview" || resp.APIVersion != "authentication.k8s.io/v1" {
				t.Errorf("response TypeMeta = %s/%s, want authentication.k8s.io/v1/TokenReview", resp.APIVersion, resp.Kind)
			}
			if tt.wantAuthd {
				if resp.Status.User.Username != tt.wantUsername {
					t.Errorf("username = %q, want %q", resp.Status.User.Username, tt.wantUsername)
				}
				if len(resp.Status.User.Groups) != tt.wantGroupsLen {
					t.Errorf("groups len = %d, want %d", len(resp.Status.User.Groups), tt.wantGroupsLen)
				}
			} else {
				if resp.Status.User.Username != "" {
					t.Errorf("username = %q, want empty on failure", resp.Status.User.Username)
				}
			}
		})
	}
}

func TestHandleTokenReview_WrongMethod(t *testing.T) {
	h := &WebhookHandler{jwtManager: newTestJWTManager(t), sessionClient: &fakeSessionGetter{}}
	req := httptest.NewRequest(http.MethodGet, "/webhook/token-review", nil)
	rr := httptest.NewRecorder()
	h.HandleTokenReview(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestHandleTokenReview_BadBody(t *testing.T) {
	h := &WebhookHandler{jwtManager: newTestJWTManager(t), sessionClient: &fakeSessionGetter{}}
	req := httptest.NewRequest(http.MethodPost, "/webhook/token-review", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()
	h.HandleTokenReview(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}
