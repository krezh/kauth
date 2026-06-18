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

	authnv1 "k8s.io/api/authentication/v1"
)

// fakeSessionClient implements sessionValidator for webhook tests.
type fakeSessionClient struct {
	session     *v1alpha1.OAuthSession
	validateErr error
	getErr      error
}

func (f *fakeSessionClient) ValidateSession(_ context.Context, _ string, _ v1alpha1.SessionPhase) error {
	return f.validateErr
}

func (f *fakeSessionClient) Get(_ context.Context, _ string) (*v1alpha1.OAuthSession, error) {
	return f.session, f.getErr
}

func sessionWithEmail(email string) *v1alpha1.OAuthSession {
	return &v1alpha1.OAuthSession{
		Status: v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionActive,
			Email: email,
		},
	}
}

// newTestHandler builds a WebhookHandler with injected fakes, bypassing the
// real OIDC provider. verify decides what the token "contains".
func newTestHandler(sc sessionValidator, verify func(context.Context, string) (*OIDCClaims, error)) *WebhookHandler {
	return &WebhookHandler{sessionClient: sc, verifyToken: verify}
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
	verifyOK := func(_ context.Context, _ string) (*OIDCClaims, error) {
		return &OIDCClaims{Email: email, Groups: []string{"devs"}}, nil
	}
	verifyFail := func(_ context.Context, _ string) (*OIDCClaims, error) {
		return nil, fmt.Errorf("bad signature")
	}

	tests := []struct {
		name          string
		token         string
		session       sessionValidator
		verify        func(context.Context, string) (*OIDCClaims, error)
		wantAuthd     bool
		wantUsername  string
		wantGroupsLen int
	}{
		{
			name:          "valid compound token with active matching session",
			token:         "kauth_sess123.header.payload.sig",
			session:       &fakeSessionClient{session: sessionWithEmail(email)},
			verify:        verifyOK,
			wantAuthd:     true,
			wantUsername:  email,
			wantGroupsLen: 1,
		},
		{
			name:      "revoked session is rejected",
			token:     "kauth_sess123.header.payload.sig",
			session:   &fakeSessionClient{validateErr: fmt.Errorf("session is Revoked, expected Active")},
			verify:    verifyOK,
			wantAuthd: false,
		},
		{
			name:      "session not found is rejected",
			token:     "kauth_sess123.header.payload.sig",
			session:   &fakeSessionClient{validateErr: fmt.Errorf("session not found")},
			verify:    verifyOK,
			wantAuthd: false,
		},
		{
			name:      "email mismatch is rejected",
			token:     "kauth_sess123.header.payload.sig",
			session:   &fakeSessionClient{session: sessionWithEmail("someone-else@example.com")},
			verify:    verifyOK,
			wantAuthd: false,
		},
		{
			name:      "bare OIDC token without prefix is rejected",
			token:     "header.payload.sig",
			session:   &fakeSessionClient{session: sessionWithEmail(email)},
			verify:    verifyOK,
			wantAuthd: false,
		},
		{
			name:      "malformed compound token without separator is rejected",
			token:     "kauth_sess123",
			session:   &fakeSessionClient{session: sessionWithEmail(email)},
			verify:    verifyOK,
			wantAuthd: false,
		},
		{
			name:      "invalid ID token signature is rejected",
			token:     "kauth_sess123.header.payload.sig",
			session:   &fakeSessionClient{session: sessionWithEmail(email)},
			verify:    verifyFail,
			wantAuthd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(tt.session, tt.verify)
			rr := postTokenReview(t, h, tt.token)

			// Authentication outcomes always return HTTP 200.
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
	h := newTestHandler(&fakeSessionClient{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/webhook/token-review", nil)
	rr := httptest.NewRecorder()
	h.HandleTokenReview(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestHandleTokenReview_BadBody(t *testing.T) {
	h := newTestHandler(&fakeSessionClient{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/webhook/token-review", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()
	h.HandleTokenReview(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}
