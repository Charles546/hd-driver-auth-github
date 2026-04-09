// Copyright 2026 Chun Huang (Charles).

// This Source Code Form is dual-licensed.
// By default, this file is licensed under the GNU Affero General Public License v3.0.
// If you have a separate written commercial agreement, you may use this file under those terms instead.

// Package hd-driver-auth-github enables Honeydipper to authenticate/authorize
// incoming web requests via GitHub OAuth2 and Casbin policies.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/honeydipper/honeydipper/v4/pkg/dipper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	ErrInvalidBearerToken  = errors.New("invalid bearer token")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidTokenFormat  = errors.New("invalid token format")
	ErrGitHubTokenExpired  = errors.New("github access token expired")
	ErrMissingClientConfig = errors.New("missing GitHub OAuth client configuration")
	ErrUserNotAuthorized   = errors.New("user not allowed by GitHub login restrictions")
	ErrGitHubAPIFailed     = errors.New("GitHub API request failed")
)

// GitHubUser represents a GitHub user retrieved from the API
type GitHubUser struct {
	Login string `json:"login"`
	Email string `json:"email"`
	ID    int    `json:"id"`
	Name  string `json:"name"`
}

// GitHubOrg represents a GitHub organization membership
type GitHubOrg struct {
	Login string `json:"login"`
}

// SessionToken represents a JWT session token payload
type SessionToken struct {
	Subject         string   `json:"sub"`
	Email           string   `json:"email"`
	Name            string   `json:"name,omitempty"`
	Organizations   []string `json:"org,omitempty"`
	GitHubID        int      `json:"github_id"`
	GitHubToken     string   `json:"github_token,omitempty"`
	GitHubTokenExp  int64    `json:"github_token_exp,omitempty"`
	GitHubRefresh   string   `json:"github_refresh_token,omitempty"`
	IssuedAt        int64    `json:"iat"`
	ExpiresAt       int64    `json:"exp"`
	AuthProviderKey string   `json:"auth_provider,omitempty"`
	jwt.RegisteredClaims
}

type authGitHubDriver struct {
	*dipper.Driver
	oauthConfig             *oauth2.Config
	tokenCache              map[string]*cachedUserInfo
	cacheMutex              sync.RWMutex
	cacheTTL                time.Duration
	cacheSize               int
	allowedUsers            map[string]bool
	allowedOrgs             map[string]bool
	allowedTeams            map[string]bool
	allowWhenNoRestrictions bool
	jwtSigningKey           []byte
	tokenExpiration         time.Duration
	httpClient              *http.Client
	apiBaseURL              string
}

type cachedUserInfo struct {
	user      *GitHubUser
	orgs      []string
	expiresAt time.Time
}

var driver = &authGitHubDriver{
	tokenCache: make(map[string]*cachedUserInfo),
	cacheTTL:   time.Hour,
	cacheSize:  1000,
}

func initFlags() {
	flag.Usage = func() {
		fmt.Printf("%s [ -h ] <service name>\n", os.Args[0])
		fmt.Printf("    This driver supports receiver and API service.\n")
		fmt.Printf("  This program provides honeydipper with GitHub OAuth2 authentication and Casbin authorization.\n")
	}
}

func main() {
	initFlags()
	flag.Parse()

	driver.Driver = dipper.NewDriver(os.Args[1], "auth-github")
	driver.RPCHandlers["auth_web_request"] = driver.authWebRequest
	driver.RPCHandlers["github_oauth_callback"] = driver.githubOAuthCallback
	driver.RPCHandlers["check_entitlements"] = driver.checkEntitlements
	driver.Reload = driver.setupConfig
	driver.Start = driver.setupConfig

	driver.Run()
}

func (d *authGitHubDriver) setupConfig(_ *dipper.Message) {
	// Initialize configuration
	if err := driver.initConfig(); err != nil {
		driver.Driver.GetLogger().Panicf("Failed to initialize auth-github driver: %v", err)
	}
}

func (d *authGitHubDriver) initConfig() error {
	log := d.GetLogger()

	// Get OAuth configuration
	clientID, ok := dipper.GetMapDataStr(d.Options, "data.client_id")
	if !ok {
		clientID = os.Getenv("GITHUB_CLIENT_ID")
	}
	if clientID == "" {
		return ErrMissingClientConfig
	}

	clientSecret, ok := dipper.GetMapDataStr(d.Options, "data.client_secret")
	if !ok {
		clientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	}
	if clientSecret == "" {
		return ErrMissingClientConfig
	}

	redirectURI, ok := dipper.GetMapDataStr(d.Options, "data.redirect_uri")
	if !ok {
		redirectURI = os.Getenv("AUTH_GITHUB_REDIRECT_URI")
	}
	if redirectURI == "" {
		redirectURI = "http://localhost:9000/api/auth/github/callback"
	}

	d.oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"user:email", "read:org"},
		Endpoint:     github.Endpoint,
	}

	// Get cache settings
	if ttl, ok := dipper.GetMapData(d.Options, "data.cache_ttl"); ok {
		if seconds, ok := ttl.(float64); ok {
			d.cacheTTL = time.Duration(int64(seconds)) * time.Second
		}
	}

	if size, ok := dipper.GetMapData(d.Options, "data.cache_size"); ok {
		if s, ok := size.(float64); ok {
			d.cacheSize = int(s)
		}
	}

	// Get token expiration
	d.tokenExpiration = 24 * time.Hour
	if expiry, ok := dipper.GetMapData(d.Options, "data.token_expiration"); ok {
		if seconds, ok := expiry.(float64); ok {
			d.tokenExpiration = time.Duration(int64(seconds)) * time.Second
		}
	}

	// Generate or load JWT signing key
	d.jwtSigningKey = []byte(clientSecret) // Use OAuth secret as JWT signing key
	if len(d.jwtSigningKey) < 32 {
		// Pad with zeros if too short
		padding := make([]byte, 32-len(d.jwtSigningKey))
		d.jwtSigningKey = append(d.jwtSigningKey, padding...)
	}

	// By default, preserve legacy behavior and allow login when no user/org restrictions are configured.
	d.allowWhenNoRestrictions = true
	if allowEmpty, ok := dipper.GetMapDataBool(d.Options, "data.allow_when_no_restrictions"); ok {
		d.allowWhenNoRestrictions = allowEmpty
	}

	// Get allowed users
	d.allowedUsers = make(map[string]bool)
	if users, ok := dipper.GetMapData(d.Options, "data.allowed_users"); ok {
		if userList, ok := users.([]interface{}); ok {
			for _, user := range userList {
				if userStr, ok := user.(string); ok {
					normalizedUser := strings.ToLower(strings.TrimSpace(userStr))
					if normalizedUser != "" {
						d.allowedUsers[normalizedUser] = true
					}
				}
			}
		}
	}

	// Get allowed organizations
	d.allowedOrgs = make(map[string]bool)
	if orgs, ok := dipper.GetMapData(d.Options, "data.allowed_orgs"); ok {
		if orgList, ok := orgs.([]interface{}); ok {
			for _, org := range orgList {
				if orgStr, ok := org.(string); ok {
					normalizedOrg := strings.ToLower(strings.TrimSpace(orgStr))
					if normalizedOrg != "" {
						d.allowedOrgs[normalizedOrg] = true
					}
				}
			}
		}
	}

	// Get allowed teams (format: org:team)
	d.allowedTeams = make(map[string]bool)
	if teams, ok := dipper.GetMapData(d.Options, "data.allowed_teams"); ok {
		if teamList, ok := teams.([]interface{}); ok {
			for _, team := range teamList {
				if teamStr, ok := team.(string); ok {
					normalizedTeam := strings.ToLower(strings.TrimSpace(teamStr))
					if normalizedTeam != "" {
						d.allowedTeams[normalizedTeam] = true
					}
				}
			}
		}
	}

	log.Debugf("[%s] GitHub OAuth2 driver initialized with Client ID: %s", d.Service, clientID)
	return nil
}

func (d *authGitHubDriver) isLoginAllowed(login string, orgs []string) bool {
	hasUserRestrictions := len(d.allowedUsers) > 0
	hasOrgRestrictions := len(d.allowedOrgs) > 0

	if !hasUserRestrictions && !hasOrgRestrictions {
		return d.allowWhenNoRestrictions
	}

	if hasUserRestrictions {
		normalizedLogin := strings.ToLower(strings.TrimSpace(login))
		if normalizedLogin == "" || !d.allowedUsers[normalizedLogin] {
			return false
		}
	}

	if hasOrgRestrictions {
		for _, org := range orgs {
			normalizedOrg := strings.ToLower(strings.TrimSpace(org))
			if normalizedOrg != "" && d.allowedOrgs[normalizedOrg] {
				return true
			}
		}

		return false
	}

	return true
}

func (d *authGitHubDriver) authWebRequest(m *dipper.Message) {
	log := d.GetLogger()
	m = dipper.DeserializePayload(m)

	const bearer = "bearer "
	authHeader, ok := dipper.GetMapDataStr(m.Payload, "headers.Authorization.0")
	if !ok {
		authHeader, ok = dipper.GetMapDataStr(m.Payload, "headers.authorization.0")
	}

	if !ok || len(authHeader) <= len(bearer) || !strings.EqualFold(authHeader[:len(bearer)], bearer) {
		log.Debugf("[%s] No valid Bearer token found", d.Service)
		panic(ErrInvalidBearerToken)
	}

	tokenString := authHeader[len(bearer):]
	claims, err := d.verifyAndExtractClaims(tokenString)
	if err != nil {
		log.Debugf("[%s] Token verification failed: %v", d.Service, err)
		panic(err)
	}

	refreshed, err := d.ensureGitHubTokenValid(claims)
	if err != nil {
		log.Debugf("[%s] GitHub token validation/refresh failed: %v", d.Service, err)
		panic(err)
	}

	rotatedJWT := ""
	if refreshed {
		rotatedJWT, err = d.signClaims(claims)
		if err != nil {
			log.Debugf("[%s] Failed to mint rotated session token: %v", d.Service, err)
			panic(err)
		}
	}

	principal := d.principalFromClaims(claims, rotatedJWT)
	log.Debugf("[%s] Successfully authenticated user: %s", d.Service, claims.Subject)
	m.Reply <- dipper.Message{
		Payload: principal,
	}
}

func (d *authGitHubDriver) verifyAndExtractClaims(tokenString string) (*SessionToken, error) {
	token := &SessionToken{}
	parsed, err := jwt.ParseWithClaims(tokenString, token, func(token *jwt.Token) (interface{}, error) {
		return d.jwtSigningKey, nil
	})

	if err != nil {
		return nil, ErrInvalidTokenFormat
	}

	claims, ok := parsed.Claims.(*SessionToken)
	if !ok || !parsed.Valid {
		return nil, ErrInvalidTokenFormat
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

func (d *authGitHubDriver) verifyAndExtractToken(tokenString string) (string, error) {
	claims, err := d.verifyAndExtractClaims(tokenString)
	if err != nil {
		return "", err
	}

	return claims.Subject, nil
}

func (d *authGitHubDriver) ensureGitHubTokenValid(claims *SessionToken) (bool, error) {
	if claims == nil || claims.GitHubToken == "" {
		return false, nil
	}

	// If expiry is not present (legacy tokens), keep existing behavior.
	if claims.GitHubTokenExp == 0 {
		return false, nil
	}

	// Refresh a little early to avoid races around boundary timestamps.
	if time.Now().Unix() < claims.GitHubTokenExp-30 {
		return false, nil
	}

	if claims.GitHubRefresh == "" {
		return false, ErrGitHubTokenExpired
	}

	refreshed, err := d.oauthConfig.TokenSource(context.Background(), &oauth2.Token{
		AccessToken:  claims.GitHubToken,
		RefreshToken: claims.GitHubRefresh,
		Expiry:       time.Unix(claims.GitHubTokenExp, 0),
	}).Token()
	if err != nil {
		return false, err
	}

	if refreshed.AccessToken != "" {
		claims.GitHubToken = refreshed.AccessToken
	}
	if refreshed.RefreshToken != "" {
		claims.GitHubRefresh = refreshed.RefreshToken
	}
	if !refreshed.Expiry.IsZero() {
		claims.GitHubTokenExp = refreshed.Expiry.Unix()
	}

	return true, nil
}

func (d *authGitHubDriver) signClaims(claims *SessionToken) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(d.jwtSigningKey)
}

func (d *authGitHubDriver) githubOAuthCallback(m *dipper.Message) {
	log := d.GetLogger()
	m = dipper.DeserializePayload(m)

	// Parse authorization code
	code, ok := dipper.GetMapDataStr(m.Payload, "code")
	if !ok {
		panic(errors.New("authorization code not provided"))
	}

	ctx := context.Background()

	// Exchange code for token
	oauthToken, err := d.oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Debugf("[%s] Failed to exchange OAuth code: %v", d.Service, err)
		panic(err)
	}

	// Get GitHub user info
	githubUser, err := d.getGitHubUser(ctx, oauthToken.AccessToken)
	if err != nil {
		log.Debugf("[%s] Failed to get GitHub user info: %v", d.Service, err)
		panic(err)
	}

	orgs, err := d.getUserOrganizations(ctx, oauthToken.AccessToken)
	if err != nil {
		log.Debugf("[%s] Failed to get user organizations: %v", d.Service, err)
		orgs = []string{}
	}

	if !d.isLoginAllowed(githubUser.Login, orgs) {
		log.Debugf(
			"[%s] User %s denied by login restrictions (allowed_users=%d, allowed_orgs=%d, allow_when_no_restrictions=%t)",
			d.Service,
			githubUser.Login,
			len(d.allowedUsers),
			len(d.allowedOrgs),
			d.allowWhenNoRestrictions,
		)
		panic(ErrUserNotAuthorized)
	}

	d.cacheMutex.Lock()
	d.tokenCache[githubUser.Login] = &cachedUserInfo{
		user:      githubUser,
		orgs:      orgs,
		expiresAt: time.Now().Add(d.cacheTTL),
	}
	d.cacheMutex.Unlock()

	// Create session token
	sessionToken, err := d.createSessionToken(githubUser, oauthToken, orgs)
	if err != nil {
		log.Debugf("[%s] Failed to create session token: %v", d.Service, err)
		panic(err)
	}

	log.Debugf("[%s] Successfully authenticated GitHub user: %s", d.Service, githubUser.Login)
	m.Reply <- dipper.Message{
		Payload: map[string]interface{}{
			"token":    sessionToken,
			"username": githubUser.Login,
			"email":    githubUser.Email,
		},
	}
}

func (d *authGitHubDriver) getGitHubUser(ctx context.Context, token string) (*GitHubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.githubAPIURL("/user"), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := d.getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user GitHubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (d *authGitHubDriver) getUserOrganizations(ctx context.Context, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.githubAPIURL("/user/orgs"), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := d.getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var orgs []GitHubOrg
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, err
	}

	var orgNames []string
	for _, org := range orgs {
		orgNames = append(orgNames, org.Login)
	}

	return orgNames, nil
}

func (d *authGitHubDriver) createSessionToken(user *GitHubUser, oauthToken *oauth2.Token, orgs []string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(d.tokenExpiration)
	accessToken := ""
	refreshToken := ""
	githubTokenExp := int64(0)
	if oauthToken != nil {
		accessToken = oauthToken.AccessToken
		refreshToken = oauthToken.RefreshToken
		if !oauthToken.Expiry.IsZero() {
			githubTokenExp = oauthToken.Expiry.Unix()
		}
	}

	claims := &SessionToken{
		Subject:         user.Login,
		Email:           user.Email,
		Name:            user.Name,
		Organizations:   orgs,
		GitHubID:        user.ID,
		GitHubToken:     accessToken,
		GitHubTokenExp:  githubTokenExp,
		GitHubRefresh:   refreshToken,
		AuthProviderKey: "auth-github",
		IssuedAt:        now.Unix(),
		ExpiresAt:       expiresAt.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	tokenString, err := d.signClaims(claims)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (d *authGitHubDriver) principalFromClaims(claims *SessionToken, rotatedJWT string) map[string]interface{} {
	profileName := claims.Name
	if profileName == "" {
		profileName = claims.Subject
	}

	data := map[string]interface{}{}
	if claims.Email != "" {
		data["email"] = claims.Email
	}
	if claims.GitHubToken != "" {
		data["accessToken"] = claims.GitHubToken
	}
	if claims.GitHubTokenExp > 0 {
		data["accessTokenExp"] = claims.GitHubTokenExp
	}
	if len(claims.Organizations) > 0 {
		data["organizations"] = claims.Organizations
	}
	if rotatedJWT != "" {
		data["rotatedJwt"] = rotatedJWT
	}

	return map[string]interface{}{
		"Subject":     claims.Subject,
		"ProfileName": profileName,
		"Data":        data,
	}
}

func (d *authGitHubDriver) getHTTPClient() *http.Client {
	if d.httpClient != nil {
		return d.httpClient
	}

	return http.DefaultClient
}

func (d *authGitHubDriver) githubAPIURL(path string) string {
	base := strings.TrimSuffix(d.apiBaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}

	return base + path
}

func (d *authGitHubDriver) generateStateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
