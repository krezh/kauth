package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"kauth/pkg/audit"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const proxyAuthenticationTimeout = 10 * time.Second

// KubernetesProxyHandler authenticates kubectl and proxies requests under the
// corresponding Kubernetes user identity.
type KubernetesProxyHandler struct {
	authenticator *SessionAuthenticator
	proxy         *httputil.ReverseProxy
}

func NewKubernetesProxyHandler(authenticator *SessionAuthenticator, upstream *url.URL, transport http.RoundTripper) *KubernetesProxyHandler {
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(upstream)
			request.Out.Host = upstream.Host
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.ErrorContext(r.Context(), "Kubernetes API proxy failed", "error", err)
		writeKubernetesStatus(w, http.StatusBadGateway, metav1.StatusReasonServiceUnavailable, "Kubernetes API is unavailable")
	}

	return &KubernetesProxyHandler{authenticator: authenticator, proxy: proxy}
}

func (h *KubernetesProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	rw := &auditResponseWriter{ResponseWriter: w, status: http.StatusOK}
	var identity *Identity
	defer func() {
		var sessionID, username string
		var groups []string
		if identity != nil {
			sessionID = identity.SessionID
			username = identity.Username
			groups = identity.Groups
		}
		audit.KubernetesRequest(r.Context(), r, sessionID, username, groups, identity != nil, rw.status, rw.bytes, time.Since(started))
	}()

	rawToken, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		h.unauthorized(rw)
		return
	}

	authCtx, cancel := context.WithTimeout(r.Context(), proxyAuthenticationTimeout)
	var err error
	identity, err = h.authenticator.Authenticate(authCtx, rawToken)
	cancel()
	if err != nil {
		identity = nil
		if errors.Is(err, ErrSessionStoreUnavailable) {
			writeKubernetesStatus(rw, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, "session store unavailable")
			return
		}
		h.unauthorized(rw)
		return
	}

	// Client-supplied identity and credentials must never reach the API server.
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "impersonate-") {
			r.Header.Del(name)
		}
	}
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	r.Header.Set("Impersonate-User", identity.Username)
	r.Header.Add("Impersonate-Group", "system:authenticated")
	for _, group := range identity.Groups {
		// Kubernetes reserves system:* groups, including system:masters.
		if group != "" && !strings.HasPrefix(strings.ToLower(group), "system:") {
			r.Header.Add("Impersonate-Group", group)
		}
	}

	h.proxy.ServeHTTP(rw, r)
}

func (h *KubernetesProxyHandler) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeKubernetesStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized, "Unauthorized")
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController retain flush, hijack, and upgrade support.
func (w *auditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.ContainsAny(token, " \t")
}

func writeKubernetesStatus(w http.ResponseWriter, code int, reason metav1.StatusReason, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Message:  message,
		Reason:   reason,
		Code:     int32(code),
	}); err != nil {
		slog.Error("failed to encode Kubernetes status", "error", err)
	}
}
