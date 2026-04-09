// Copyright 2026 Chun Huang (Charles).

// This Source Code Form is dual-licensed.
// By default, this file is licensed under the GNU Affero General Public License v3.0.
// If you have a separate written commercial agreement, you may use this file under those terms instead.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/honeydipper/honeydipper/v4/pkg/dipper"
	"golang.org/x/oauth2"
)

func TestCreateSessionToken(t *testing.T) {
	driver := &authGitHubDriver{
		jwtSigningKey:   []byte("test-secret-key-32-bytes-long!!!"),
		tokenExpiration: time.Hour,
	}

	user := &GitHubUser{
		Login: "testuser",
		Email: "test@example.com",
		ID:    12345,
		Name:  "Test User",
	}

	tokenStr, err := driver.createSessionToken(user, &oauth2.Token{
		AccessToken:  "gh-access-token",
		RefreshToken: "gh-refresh-token",
		Expiry:       time.Now().Add(30 * time.Minute),
	}, []string{"honeydipper"})
	if err != nil {
		t.Fatalf("createSessionToken failed: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("token string is empty")
	}

	// Verify token can be parsed
	token := &SessionToken{}
	parsed, err := jwt.ParseWithClaims(tokenStr, token, func(token *jwt.Token) (interface{}, error) {
		return driver.jwtSigningKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims, ok := parsed.Claims.(*SessionToken)
	if !ok {
		t.Fatal("failed to extract claims")
	}

	if claims.Subject != "testuser" {
		t.Errorf("expected subject 'testuser', got '%s'", claims.Subject)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", claims.Email)
	}

	if claims.GitHubID != 12345 {
		t.Errorf("expected GitHub ID 12345, got %d", claims.GitHubID)
	}

	if claims.Name != "Test User" {
		t.Errorf("expected name 'Test User', got '%s'", claims.Name)
	}

	if claims.GitHubToken != "gh-access-token" {
		t.Errorf("expected GitHub token to round-trip")
	}

	if claims.GitHubRefresh != "gh-refresh-token" {
		t.Errorf("expected GitHub refresh token to round-trip")
	}

	if claims.GitHubTokenExp == 0 {
		t.Errorf("expected GitHub token expiry to be set")
	}
}

func TestVerifyAndExtractToken(t *testing.T) {
	driver := &authGitHubDriver{
		jwtSigningKey:   []byte("test-secret-key-32-bytes-long!!!"),
		tokenExpiration: time.Hour,
	}

	user := &GitHubUser{
		Login: "testuser",
		Email: "test@example.com",
		ID:    12345,
		Name:  "Test User",
	}

	// Create a valid token
	tokenStr, err := driver.createSessionToken(user, &oauth2.Token{
		AccessToken: "gh-access-token",
		Expiry:      time.Now().Add(30 * time.Minute),
	}, []string{"honeydipper"})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Verify and extract
	subject, err := driver.verifyAndExtractToken(tokenStr)
	if err != nil {
		t.Fatalf("verifyAndExtractToken failed: %v", err)
	}

	if subject != "testuser" {
		t.Errorf("expected subject 'testuser', got '%s'", subject)
	}
}

func TestVerifyAndExtractTokenExpired(t *testing.T) {
	driver := &authGitHubDriver{
		jwtSigningKey:   []byte("test-secret-key-32-bytes-long!!!"),
		tokenExpiration: -time.Hour, // Expired token
	}

	user := &GitHubUser{
		Login: "testuser",
		Email: "test@example.com",
		ID:    12345,
		Name:  "Test User",
	}

	// Create an expired token
	tokenStr, err := driver.createSessionToken(user, &oauth2.Token{
		AccessToken: "gh-access-token",
		Expiry:      time.Now().Add(30 * time.Minute),
	}, nil)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Verify and extract - should fail with ErrTokenExpired
	_, err = driver.verifyAndExtractToken(tokenStr)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestEnsureGitHubTokenValidRefreshesExpiredToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST to token endpoint, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed parsing token request form: %v", err)
		}

		if got := r.FormValue("grant_type"); got != "refresh_token" {
			t.Fatalf("expected refresh_token grant, got %q", got)
		}
		if got := r.FormValue("refresh_token"); got != "old-refresh" {
			t.Fatalf("expected refresh token old-refresh, got %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","token_type":"bearer","expires_in":3600,"refresh_token":"new-refresh"}`)
	}))
	defer server.Close()

	driver := &authGitHubDriver{
		oauthConfig: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL,
			},
		},
	}

	claims := &SessionToken{
		GitHubToken:    "old-access",
		GitHubRefresh:  "old-refresh",
		GitHubTokenExp: time.Now().Add(-time.Minute).Unix(),
	}

	refreshed, err := driver.ensureGitHubTokenValid(claims)
	if err != nil {
		t.Fatalf("expected refresh to succeed, got error: %v", err)
	}
	if !refreshed {
		t.Fatalf("expected refresh indicator to be true")
	}

	if claims.GitHubToken != "new-access" {
		t.Fatalf("expected refreshed access token, got %q", claims.GitHubToken)
	}

	if claims.GitHubRefresh != "new-refresh" {
		t.Fatalf("expected refreshed refresh token, got %q", claims.GitHubRefresh)
	}

	if claims.GitHubTokenExp <= time.Now().Unix() {
		t.Fatalf("expected refreshed token expiry to be in the future")
	}
}

func TestEnsureGitHubTokenValidExpiredWithoutRefreshToken(t *testing.T) {
	driver := &authGitHubDriver{}
	claims := &SessionToken{
		GitHubToken:    "old-access",
		GitHubTokenExp: time.Now().Add(-time.Minute).Unix(),
	}

	refreshed, err := driver.ensureGitHubTokenValid(claims)
	if refreshed {
		t.Fatalf("expected refresh indicator to be false")
	}
	if err != ErrGitHubTokenExpired {
		t.Fatalf("expected ErrGitHubTokenExpired, got %v", err)
	}
}

func TestVerifyAndExtractTokenInvalid(t *testing.T) {
	driver := &authGitHubDriver{
		jwtSigningKey:   []byte("test-secret-key-32-bytes-long!!!"),
		tokenExpiration: time.Hour,
	}

	// Invalid token string
	_, err := driver.verifyAndExtractToken("invalid.token.string")
	if err != ErrInvalidTokenFormat {
		t.Errorf("expected ErrInvalidTokenFormat, got %v", err)
	}
}

func TestGenerateStateToken(t *testing.T) {
	driver := &authGitHubDriver{}

	token1, err := driver.generateStateToken()
	if err != nil {
		t.Fatalf("generateStateToken failed: %v", err)
	}

	token2, err := driver.generateStateToken()
	if err != nil {
		t.Fatalf("generateStateToken failed: %v", err)
	}

	// Tokens should be different
	if token1 == token2 {
		t.Error("generated tokens should be unique")
	}

	// Tokens should not be empty
	if token1 == "" || token2 == "" {
		t.Error("generated tokens should not be empty")
	}
}

func TestPrincipalFromClaims(t *testing.T) {
	driver := &authGitHubDriver{}
	principal := driver.principalFromClaims(&SessionToken{
		Subject:       "testuser",
		Name:          "Test User",
		Email:         "test@example.com",
		GitHubToken:   "gh-access-token",
		Organizations: []string{"honeydipper"},
	}, "rotated-jwt")

	if principal["Subject"] != "testuser" {
		t.Fatalf("expected subject in principal")
	}

	if principal["ProfileName"] != "Test User" {
		t.Fatalf("expected profile name in principal")
	}

	data, ok := principal["Data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected principal data map")
	}

	if data["accessToken"] != "gh-access-token" {
		t.Fatalf("expected access token in principal data")
	}

	if data["rotatedJwt"] != "rotated-jwt" {
		t.Fatalf("expected rotated JWT in principal data")
	}
}

func TestIsLoginAllowed_EmptyRestrictionsDisallowed(t *testing.T) {
	driver := &authGitHubDriver{
		allowWhenNoRestrictions: false,
	}

	if driver.isLoginAllowed("alice", nil) {
		t.Fatalf("expected login to be denied when no restrictions are configured and allow_when_no_restrictions is false")
	}
}

func TestIsLoginAllowed_EmptyRestrictionsAllowed(t *testing.T) {
	driver := &authGitHubDriver{
		allowWhenNoRestrictions: true,
	}

	if !driver.isLoginAllowed("alice", nil) {
		t.Fatalf("expected login to be allowed when no restrictions are configured and allow_when_no_restrictions is true")
	}
}

func TestIsLoginAllowed_AllowedUsersOnly(t *testing.T) {
	driver := &authGitHubDriver{
		allowedUsers:            map[string]bool{"alice": true},
		allowWhenNoRestrictions: true,
	}

	if !driver.isLoginAllowed("Alice", nil) {
		t.Fatalf("expected configured user to be allowed")
	}

	if driver.isLoginAllowed("bob", nil) {
		t.Fatalf("expected non-configured user to be denied")
	}
}

func TestIsLoginAllowed_AllowedOrgsOnly(t *testing.T) {
	driver := &authGitHubDriver{
		allowedOrgs:             map[string]bool{"engineering": true},
		allowWhenNoRestrictions: true,
	}

	if !driver.isLoginAllowed("alice", []string{"Engineering", "security"}) {
		t.Fatalf("expected user in allowed organization to be allowed")
	}

	if driver.isLoginAllowed("alice", []string{"sales"}) {
		t.Fatalf("expected user outside allowed organizations to be denied")
	}
}

func TestIsLoginAllowed_UsersAndOrgsMustBothMatch(t *testing.T) {
	driver := &authGitHubDriver{
		allowedUsers:            map[string]bool{"alice": true},
		allowedOrgs:             map[string]bool{"engineering": true},
		allowWhenNoRestrictions: true,
	}

	if !driver.isLoginAllowed("alice", []string{"engineering"}) {
		t.Fatalf("expected user to be allowed when both restrictions match")
	}

	if driver.isLoginAllowed("alice", []string{"sales"}) {
		t.Fatalf("expected user to be denied when organization restriction does not match")
	}

	if driver.isLoginAllowed("bob", []string{"engineering"}) {
		t.Fatalf("expected user to be denied when user restriction does not match")
	}
}

func TestCheckEntitlementsUsesPrincipalAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/honeydipper/honeydipper":
			if got := r.Header.Get("Authorization"); got != "Bearer gh-access-token" {
				t.Fatalf("expected bearer token to be forwarded, got %q", got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"owner":{"login":"honeydipper"},"permissions":{"push":true}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &authGitHubDriver{
		Driver:     dipper.NewDriver("test", "auth-github"),
		apiBaseURL: server.URL,
		httpClient: server.Client(),
	}

	reply := make(chan dipper.Message, 1)
	payload := map[string]interface{}{
		"principal": map[string]interface{}{
			"Subject": "testuser",
			"Data": map[string]interface{}{
				"accessToken": "gh-access-token",
			},
		},
		"entitlementTarget": "honeydipper/honeydipper",
	}

	driver.checkEntitlements(&dipper.Message{Payload: payload, Reply: reply})

	msg := <-reply
	var derived []string
	payloadBytes, ok := msg.Payload.([]byte)
	if !ok {
		t.Fatalf("expected raw byte payload, got %T", msg.Payload)
	}
	if err := json.Unmarshal(payloadBytes, &derived); err != nil {
		t.Fatalf("failed to decode derived subjects: %v", err)
	}

	if !slices.Contains(derived, "honeydipper/honeydipper") || !slices.Contains(derived, "repo:collaborators") {
		t.Fatalf("unexpected derived subjects: %#v", derived)
	}
}

func TestCheckEntitlementsReturnsOrgRoleSubjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/memberships/orgs/honeydipper":
			if got := r.Header.Get("Authorization"); got != "Bearer gh-access-token" {
				t.Fatalf("expected bearer token to be forwarded, got %q", got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"state":"active","role":"admin"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &authGitHubDriver{
		Driver:     dipper.NewDriver("test", "auth-github"),
		apiBaseURL: server.URL,
		httpClient: server.Client(),
	}

	reply := make(chan dipper.Message, 1)
	payload := map[string]interface{}{
		"principal": map[string]interface{}{
			"Subject": "testuser",
			"Data": map[string]interface{}{
				"accessToken": "gh-access-token",
			},
		},
		"entitlementTarget": "honeydipper",
	}

	driver.checkEntitlements(&dipper.Message{Payload: payload, Reply: reply})

	msg := <-reply
	var derived []string
	payloadBytes, ok := msg.Payload.([]byte)
	if !ok {
		t.Fatalf("expected raw byte payload, got %T", msg.Payload)
	}
	if err := json.Unmarshal(payloadBytes, &derived); err != nil {
		t.Fatalf("failed to decode derived subjects: %v", err)
	}

	if !slices.Contains(derived, "honeydipper") || !slices.Contains(derived, "org:owners") || !slices.Contains(derived, "org:members") || !slices.Contains(derived, "org:collaborators") {
		t.Fatalf("unexpected derived subjects: %#v", derived)
	}
}
