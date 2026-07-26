package handlers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestRefreshHandler_HTTPIntegration(t *testing.T) {
	const (
		issuer          = "https://issuer.example.test"
		clientID        = "kauth-test-client"
		clientSecret    = "kauth-test-secret"
		email           = "alice@example.com"
		username        = "alice"
		sessionID       = "refresh-integration-session"
		oldOIDCRefresh  = "upstream-refresh-old"
		newOIDCRefresh  = "upstream-refresh-new"
		requestID       = "refresh-request-000001"
		namespace       = "kauth-test"
		refreshTokenTTL = 12 * time.Hour
	)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ID token key: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		t.Fatalf("create ID token signer: %v", err)
	}
	idTokenExpiry := time.Now().Add(15 * time.Minute).Truncate(time.Second)
	idToken, err := josejwt.Signed(signer).
		Claims(josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Audience: josejwt.Audience{clientID},
			Expiry:   josejwt.NewNumericDate(idTokenExpiry),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		}).
		Claims(struct {
			Email             string   `json:"email"`
			Groups            []string `json:"groups"`
			Name              string   `json:"name"`
			PreferredUsername string   `json:"preferred_username"`
		}{
			Email:             email,
			Groups:            []string{"developers", "platform"},
			Name:              "Alice Example",
			PreferredUsername: username,
		}).
		Serialize()
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}

	var upstreamCalls atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != oldOIDCRefresh {
			http.Error(w, "unexpected refresh request", http.StatusBadRequest)
			return
		}
		gotClientID, gotClientSecret, ok := r.BasicAuth()
		if !ok || gotClientID != clientID || gotClientSecret != clientSecret {
			http.Error(w, "invalid client credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-new",
			"refresh_token": newOIDCRefresh,
			"id_token":      idToken,
			"token_type":    "Bearer",
			"expires_in":    900,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	t.Cleanup(tokenServer.Close)

	provider := &oauth.Provider{
		OAuth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				TokenURL:  tokenServer.URL,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		IDTokenVerifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{&privateKey.PublicKey},
		}, &oidc.Config{ClientID: clientID}),
	}

	jwtManager := newTestJWTManager(t)
	oldRefreshToken, err := jwtManager.CreateRefreshToken(email, oldOIDCRefresh, sessionID, 0, refreshTokenTTL)
	if err != nil {
		t.Fatalf("create initial refresh token: %v", err)
	}
	oldWebhookToken, err := jwtManager.CreateWebhookToken(sessionID, refreshTokenTTL)
	if err != nil {
		t.Fatalf("create initial webhook token: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register OAuthSession scheme: %v", err)
	}
	gvr := schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "oauthsessions"}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		gvr: "OAuthSessionList",
	})
	sessionClient := session.NewClientForDynamic(dynamicClient, namespace)
	if _, err := sessionClient.Create(context.Background(), sessionID, "unused-verifier", email); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := sessionClient.UpdateStatus(context.Background(), sessionID, v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        email,
		Username:     username,
		RefreshToken: oldRefreshToken,
		WebhookToken: oldWebhookToken,
		Groups:       []string{"developers"},
	}); err != nil {
		t.Fatalf("activate session: %v", err)
	}
	var failRotation atomic.Bool
	failRotation.Store(true)
	dynamicClient.PrependReactor("update", "oauthsessions", func(action clienttesting.Action) (bool, runtime.Object, error) {
		update := action.(clienttesting.UpdateAction)
		if update.GetSubresource() == "status" && failRotation.CompareAndSwap(true, false) {
			return true, nil, errors.New("injected status update failure")
		}
		return false, nil, nil
	})

	handler := NewRefreshHandler(
		provider,
		jwtManager,
		sessionClient,
		"integration-cluster",
		"https://kubernetes.example.test",
		base64.StdEncoding.EncodeToString([]byte("test-cluster-ca")),
		refreshTokenTTL,
		[]string{"developers"},
	)
	requestBody, err := json.Marshal(RefreshRequest{RefreshToken: oldRefreshToken, RequestID: requestID})
	if err != nil {
		t.Fatalf("marshal refresh request: %v", err)
	}

	failedRecorder := httptest.NewRecorder()
	handler.HandleRefresh(failedRecorder, httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(requestBody)))
	if failedRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("refresh with injected commit failure status = %d, want %d (body=%s)", failedRecorder.Code, http.StatusInternalServerError, failedRecorder.Body.String())
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls after staged commit failure = %d, want 1", got)
	}

	firstRecorder := httptest.NewRecorder()
	handler.HandleRefresh(firstRecorder, httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(requestBody)))
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("first refresh status = %d, want %d (body=%s)", firstRecorder.Code, http.StatusOK, firstRecorder.Body.String())
	}
	var firstResponse RefreshResponse
	if err := json.Unmarshal(firstRecorder.Body.Bytes(), &firstResponse); err != nil {
		t.Fatalf("decode first refresh response: %v", err)
	}
	if firstResponse.RefreshToken == "" || firstResponse.RefreshToken == oldRefreshToken {
		t.Fatalf("refresh token was not replaced: %q", firstResponse.RefreshToken)
	}
	if firstResponse.WebhookToken == "" || firstResponse.WebhookToken == oldWebhookToken {
		t.Fatalf("webhook token was not replaced: %q", firstResponse.WebhookToken)
	}
	if !firstResponse.SessionExpiry.After(time.Now()) {
		t.Fatalf("session expiry = %s, want a future time", firstResponse.SessionExpiry)
	}
	if firstResponse.IDToken != idToken {
		t.Error("response did not contain the verified upstream ID token")
	}
	newRefreshCredential, err := jwtManager.DecodeRefreshToken(firstResponse.RefreshToken)
	if err != nil {
		t.Fatalf("decode replacement refresh token: %v", err)
	}
	if newRefreshCredential.OIDCRefreshToken != newOIDCRefresh || newRefreshCredential.RotationCounter != 1 {
		t.Errorf("replacement refresh credential = %+v, want rotated upstream token and counter 1", newRefreshCredential)
	}
	newWebhookCredential, err := jwtManager.DecodeWebhookToken(firstResponse.WebhookToken)
	if err != nil {
		t.Fatalf("decode replacement webhook token: %v", err)
	}
	if newWebhookCredential.SessionID != sessionID || !newWebhookCredential.ExpiresAt.Equal(firstResponse.SessionExpiry) {
		t.Errorf("replacement webhook credential = %+v, response expiry = %s", newWebhookCredential, firstResponse.SessionExpiry)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls after first refresh = %d, want 1", got)
	}

	storedSession, err := sessionClient.Get(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("get rotated session: %v", err)
	}
	if storedSession.Status.RefreshToken != firstResponse.RefreshToken {
		t.Errorf("stored refresh token = %q, want response replacement", storedSession.Status.RefreshToken)
	}
	if storedSession.Status.WebhookToken != firstResponse.WebhookToken {
		t.Errorf("stored webhook token = %q, want response replacement", storedSession.Status.WebhookToken)
	}

	retryRecorder := httptest.NewRecorder()
	handler.HandleRefresh(retryRecorder, httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(requestBody)))
	if retryRecorder.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d (body=%s)", retryRecorder.Code, http.StatusOK, retryRecorder.Body.String())
	}
	var retryResponse RefreshResponse
	if err := json.Unmarshal(retryRecorder.Body.Bytes(), &retryResponse); err != nil {
		t.Fatalf("decode retry response: %v", err)
	}
	if !reflect.DeepEqual(retryResponse, firstResponse) {
		t.Errorf("retry response differs from staged response\nfirst: %+v\nretry: %+v", firstResponse, retryResponse)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Errorf("upstream calls after exact retry = %d, want 1", got)
	}
}

func TestRefreshRequiresRequestID(t *testing.T) {
	handler := &RefreshHandler{}
	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBufferString(`{"refresh_token":"token"}`))
	resp := httptest.NewRecorder()
	handler.HandleRefresh(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}
