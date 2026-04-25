// Copyright 2026 Chun Huang (Charles).

// This Source Code Form is dual-licensed.
// By default, this file is licensed under the GNU Affero General Public License v3.0.
// If you have a separate written commercial agreement, you may use this file under those terms instead.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/honeydipper/honeydipper/v4/pkg/dipper"
)

// checkEntitlements verifies if a user has access to a given GitHub target.
// The target is a gh_slug that can be either an org or an owner/repo pair.
func (d *authGitHubDriver) checkEntitlements(m *dipper.Message) {
	log := d.GetLogger()
	m = dipper.DeserializePayload(m)

	principalData, ok := dipper.GetMapData(m.Payload, "principal")
	if !ok {
		log.Debugf("[%s] Missing principal in check_entitlements request", d.Service)
		panic(errors.New("missing principal"))
	}

	principalMap, ok := principalData.(map[string]interface{})
	if !ok {
		log.Debugf("[%s] Invalid principal format in check_entitlements request", d.Service)
		panic(errors.New("invalid principal format"))
	}

	subject, ok := getPrincipalString(principalMap, "Subject", "subject")
	if !ok || subject == "" {
		log.Debugf("[%s] Missing subject in principal for check_entitlements", d.Service)
		panic(errors.New("missing subject in principal"))
	}
	accessToken := getPrincipalAccessToken(principalMap)

	entitlementTarget, ok := dipper.GetMapDataStr(m.Payload, "entitlementTarget")
	if !ok || entitlementTarget == "" {
		log.Debugf("[%s] Missing entitlementTarget in check_entitlements request", d.Service)
		panic(errors.New("missing entitlementTarget"))
	}

	derivedSubjects := d.deriveSubjects(subject, entitlementTarget, accessToken)
	payload := dipper.Must(json.Marshal(derivedSubjects)).([]byte)

	log.Debugf("[%s] User %s entitlement target %s resolved to %v", d.Service, subject, entitlementTarget, derivedSubjects)
	m.Reply <- dipper.Message{Payload: payload, IsRaw: true}
}

func (d *authGitHubDriver) deriveSubjects(username, entitlementTarget, accessToken string) []string {
	entitlementTarget = strings.TrimPrefix(entitlementTarget, "/")
	if strings.Contains(entitlementTarget, "/") {
		parts := strings.Split(entitlementTarget, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return []string{}
		}

		if role, ok := d.getRepoRole(username, accessToken, parts[0], parts[1]); ok {
			return buildRoleSubjects(entitlementTarget, "repo", role)
		}

		return []string{}
	}

	if role, ok := d.getOrgRole(username, accessToken, entitlementTarget); ok {
		return buildRoleSubjects(entitlementTarget, "org", role)
	}

	return []string{}
}

func buildRoleSubjects(target, kind, role string) []string {
	subjects := []string{target}
	addRole := func(r string) {
		subject := kind + ":" + r
		for _, existing := range subjects {
			if existing == subject {
				return
			}
		}
		subjects = append(subjects, subject)
	}

	addRole("members")
	switch role {
	case "owner":
		addRole("owners")
		addRole("maintainers")
		addRole("mainainers")
		addRole("collaborators")
	case "maintainer":
		addRole("maintainers")
		addRole("mainainers")
		addRole("collaborators")
	case "collaborator":
		addRole("collaborators")
	case "member":
		// members is already included
	default:
		addRole("collaborators")
	}

	return subjects
}

func getPrincipalString(principal map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		value, ok := principal[key]
		if !ok {
			continue
		}

		text, ok := value.(string)
		if ok {
			return text, true
		}
	}

	return "", false
}

func getPrincipalAccessToken(principal map[string]interface{}) string {
	dataValue, ok := principal["Data"]
	if !ok {
		dataValue = principal["data"]
	}
	data, ok := dataValue.(map[string]interface{})
	if !ok {
		return ""
	}

	for _, key := range []string{"accessToken", "access_token", "githubToken", "github_token"} {
		if token, ok := data[key].(string); ok && token != "" {
			return token
		}
	}

	return ""
}

func (d *authGitHubDriver) getOrgRole(username, accessToken, orgName string) (string, bool) {
	if strings.EqualFold(username, orgName) {
		return "owner", true
	}

	if accessToken != "" {
		membership, err := d.getOrgMembership(accessToken, orgName)
		if err == nil {
			role := normalizeOrgRole(membership.Role)
			if role != "" {
				return role, true
			}
		}
	}

	if d.isOrgMember(username, orgName) {
		return "member", true
	}

	return "", false
}

func normalizeOrgRole(role string) string {
	switch strings.ToLower(role) {
	case "admin", "owner":
		return "owner"
	case "maintainer":
		return "maintainer"
	case "member":
		return "member"
	default:
		return ""
	}
}

func (d *authGitHubDriver) getRepoRole(username, accessToken, owner, repo string) (string, bool) {
	if strings.EqualFold(username, owner) {
		return "owner", true
	}

	if accessToken != "" {
		repoInfo, err := d.getRepoAccess(accessToken, owner, repo)
		if err == nil {
			if strings.EqualFold(repoInfo.Owner.Login, username) {
				return "owner", true
			}

			if repoInfo.Permissions["admin"] {
				return "owner", true
			}
			if repoInfo.Permissions["maintain"] {
				return "maintainer", true
			}
			if repoInfo.Permissions["push"] {
				return "collaborator", true
			}
			if repoInfo.Permissions["triage"] || repoInfo.Permissions["pull"] {
				return "member", true
			}
		}
	}

	if d.isRepoCollaborator(username, owner, repo) {
		return "collaborator", true
	}

	return "", false
}

type orgMembership struct {
	State string `json:"state"`
	Role  string `json:"role"`
}

type repoOwner struct {
	Login string `json:"login"`
}

type repoAccess struct {
	Owner       repoOwner       `json:"owner"`
	Permissions map[string]bool `json:"permissions"`
}

func (d *authGitHubDriver) getOrgMembership(accessToken, orgName string) (*orgMembership, error) {
	resp, err := d.githubAPIGet(accessToken, fmt.Sprintf("/user/memberships/orgs/%s", orgName))
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

	membership := &orgMembership{}
	if err := json.Unmarshal(body, membership); err != nil {
		return nil, err
	}

	if !strings.EqualFold(membership.State, "active") {
		return nil, errors.New("organization membership is not active")
	}

	return membership, nil
}

func (d *authGitHubDriver) getRepoAccess(accessToken, owner, repo string) (*repoAccess, error) {
	resp, err := d.githubAPIGet(accessToken, fmt.Sprintf("/repos/%s/%s", owner, repo))
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

	repoInfo := &repoAccess{}
	if err := json.Unmarshal(body, repoInfo); err != nil {
		return nil, err
	}

	return repoInfo, nil
}

func (d *authGitHubDriver) githubAPIGet(accessToken, path string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.githubAPIURL(path), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	return d.getHTTPClient().Do(req)
}

// isOrgMember checks if a user is a member of an organization.
// This uses the cached organization list from authentication.
func (d *authGitHubDriver) isOrgMember(username, orgName string) bool {
	log := d.GetLogger()

	d.cacheMutex.RLock()
	cached, exists := d.tokenCache[username]
	d.cacheMutex.RUnlock()

	if !exists || cached == nil {
		log.Debugf("[%s] No cached user info for %s", d.Service, username)
		return false
	}

	if time.Now().After(cached.expiresAt) {
		log.Debugf("[%s] Cached user info for %s expired", d.Service, username)
		d.cacheMutex.Lock()
		delete(d.tokenCache, username)
		d.cacheMutex.Unlock()
		return false
	}

	for _, org := range cached.orgs {
		if strings.EqualFold(org, orgName) {
			return true
		}
	}

	return false
}

// isRepoCollaborator checks whether the target repo belongs to the user or an org they belong to.
func (d *authGitHubDriver) isRepoCollaborator(username, owner, repo string) bool {
	log := d.GetLogger()

	if strings.EqualFold(username, owner) {
		return true
	}

	if d.isOrgMember(username, owner) {
		return true
	}

	log.Debugf("[%s] User %s is not a collaborator on %s/%s", d.Service, username, owner, repo)
	return false
}
