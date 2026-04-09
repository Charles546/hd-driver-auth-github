# Web UI Integration with GitHub Auth

This guide shows how to integrate the GitHub authentication driver with Honeydipper's web UI and configure Casbin policies for authorization.

## Architecture Overview

```
User Browser
    |
    v GitHub OAuth Flow
GitHub OAuth Provider
    |
    v Authorization Code + Token
    |
    v /auth/github/callback
    |
Web UI Backend (Honeydipper API)
    |
    v auth_web_request RPC call
    |
auth-github driver
    |
    ├─> Validates JWT token
    ├─> Extracts GitHub username
    └─> Returns subject for Casbin
    |
    v Casbin enforcer
    |
    ├─> Check role assignments (g rules)
    ├─> Check policies (p rules)
    └─> Allow/Deny decision
    |
    v Return 200 OK or 403 Forbidden
    |
Web UI Backend sends response
    |
    v User sees authorized content or access denied
User Browser
```

## Step 1: GitHub App Setup

### Option A: GitHub OAuth Application

1. Go to https://github.com/settings/developers/
2. Click "New OAuth App"
3. Fill in the form:
   - **Application name**: Honeydipper
   - **Homepage URL**: https://your-domain
   - **Authorization callback URL**: https://your-domain/auth/github/callback
4. Click "Create OAuth App"
5. Copy the **Client ID** and **Client Secret**

### Option B: GitHub App

1. Go to https://github.com/settings/apps or organization settings
2. Click "New GitHub App"
3. Fill in the form:
   - **GitHub App name**: honeydipper-web
   - **Homepage URL**: https://your-domain
   - **Authorization callback URL**: https://your-domain/auth/github/callback
4. Generate a Client Secret
5. Copy Client ID and Client Secret

## Step 2: Configure Honeydipper

### Add auth-github Driver

Update your Honeydipper daemon configuration:

```yaml
drivers:
  daemon:
    services:
      api:
        auth-providers:
          - auth-github
        auth:
          casbin:
            models:
              - |
                [request_definition]
                r = sub, obj, act, provider

                [policy_definition]
                p = sub, obj, act, provider

                [role_definition]
                g = _, _

                [policy_effect]
                e = some(where (p.eft == allow))

                [matchers]
                m = (r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.provider == p.provider) \
                  || (g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act && r.provider == p.provider) \
                  || (r.sub == 'admin')

            policies:
              - |
                # Define roles
                p, viewer, webui, read, auth-github
                p, editor, webui, write, auth-github
                
                # Assign users to roles
                g, alice, editor
                g, bob, viewer
                
                # Allow specific users
                p, charlie, webui, write, auth-github

auth-github:
  data:
    client_id: ${GITHUB_CLIENT_ID}
    client_secret: ${GITHUB_CLIENT_SECRET}
    redirect_uri: https://your-domain/auth/github/callback
    allowed_users: []
    allowed_orgs: []
    allow_when_no_restrictions: true
    token_expiration: 86400
```

### Set Environment Variables

```bash
export GITHUB_CLIENT_ID="your-client-id"
export GITHUB_CLIENT_SECRET="your-client-secret"
```

### Deploy Driver

Build and deploy the auth-github driver:

```bash
cd /path/to/hd-driver-auth-github
go build -o hd-driver-auth-github ./cmd/hd-driver-auth-github
cp hd-driver-auth-github /path/to/honeydipper/drivers/
```

## Step 3: Configure Web UI

Update the web UI to use GitHub login:

```javascript
// src/auth/AuthContext.jsx
import { useContext, createContext } from 'react';

export const AuthContext = createContext();

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }) {
  const handleGitHubLogin = () => {
    // Construct GitHub OAuth URL
    const clientId = import.meta.env.VITE_GITHUB_CLIENT_ID;
    const redirectUri = `${window.location.origin}/auth/github/callback`;
    const scopes = ['user:email', 'read:org'];
    
    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', scopes.join(' '));
    authUrl.searchParams.set('allow_signup', 'true');
    
    window.location.href = authUrl.toString();
  };

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  return (
    <AuthContext.Provider value={{ handleGitHubLogin, handleLogout }}>
      {children}
    </AuthContext.Provider>
  );
}
```

Create a callback handler:

```javascript
// src/auth/GitHubCallback.jsx
import { useEffect } from 'react';
import { useAuth } from './AuthContext';

export function GitHubCallback() {
  const { handleGitHubLogin } = useAuth();
  
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const error = params.get('error');

    if (error) {
      console.error('GitHub auth error:', error);
      window.location.href = '/login?error=' + error;
      return;
    }

    if (code) {
      // Exchange code for token with backend
      fetch('/api/auth/github/callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      })
      .then(res => res.json())
      .then(data => {
        if (data.token) {
          localStorage.setItem('auth_token', data.token);
          localStorage.setItem('user', JSON.stringify({
            username: data.username,
            email: data.email
          }));
          window.location.href = '/dashboard';
        }
      })
      .catch(err => {
        console.error('Token exchange failed:', err);
        window.location.href = '/login?error=auth_failed';
      });
    }
  }, []);

  return <div>Processing GitHub authentication...</div>;
}
```

## Step 4: API Request with Token

When making API requests from the web UI, include the auth token:

```javascript
// src/api.js
export async function apiRequest(endpoint, options = {}) {
  const token = localStorage.getItem('auth_token');
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(endpoint, {
    ...options,
    headers
  });

  if (response.status === 401) {
    // Token expired or invalid
    localStorage.removeItem('auth_token');
    window.location.href = '/login';
    return;
  }

  if (response.status === 403) {
    // User not authorized
    throw new Error('Access denied');
  }

  return response.json();
}
```

## Authorization Policy Examples

### Example 1: Simple User-Based Access

```yaml
policies:
  - |
    p, alice, webui, read, auth-github
    p, bob, webui, write, auth-github
    p, charlie, webui, read, auth-github
```

### Example 2: Role-Based Access Control (RBAC)

```yaml
policies:
  - |
    # Define roles
    p, viewer, webui, read, auth-github
    p, editor, webui, write, auth-github
    p, admin, webui, write, auth-github
    
    # Assign users to roles
    g, alice, admin
    g, bob, editor
    g, charlie, viewer
    g, dave, viewer
```

### Example 3: Organization-Based Access

```yaml
policies:
  - |
    # Users from specific GitHub org get access
    # This requires including org info in JWT (see custom claims in driver)
    
    # Alternatively, use role hierarchy:
    # Assign org membership to role groups
    
    p, backend-team, webui, write, auth-github
    p, frontend-team, webui, read, auth-github
    
    g, alice, backend-team
    g, bob, frontend-team
```

### Example 4: Hierarchy and Inheritance

```yaml
policies:
  - |
    # Permission hierarchy
    p, viewer, webui, read, auth-github
    p, editor, webui, write, auth-github
    p, admin, webui, write, auth-github
    
    # Role hierarchy (implicit: editor > viewer, admin > editor)
    # This requires custom matcher logic in Casbin
    
    g, alice, admin
    g, bob, editor    # Gets both write and read through custom logic
    g, charlie, viewer
    
    # Everyone can see public content
    p, everyone, webui, read, auth-github
```

## Entitlement Subject Mapping for gh_event APIs

When an API definition uses `entitlement_provider: auth-github`, Honeydipper calls `check_entitlements` and evaluates Casbin rules against the returned `derivedSubjects`.

For organization targets (`entitlementTarget: <org>`), the driver returns:
- `<org>`
- `org:members`
- `org:collaborators`
- `org:maintainers`
- `org:owners`

For repository targets (`entitlementTarget: <owner>/<repo>`), the driver returns:
- `<owner>/<repo>`
- `repo:members`
- `repo:collaborators`
- `repo:maintainers`
- `repo:owners`

Compatibility aliases are also emitted:
- `org:mainainers`
- `repo:mainainers`

Use these subjects directly in Casbin policies:

```yaml
policies:
  - |
    p, org:owners, gh_event, read, auth-github
    p, org:maintainers, gh_event, read, auth-github
    p, org:mainainers, gh_event, read, auth-github
    p, org:members, gh_event, read, auth-github
    p, org:collaborators, gh_event, read, auth-github
    p, repo:owners, gh_event, read, auth-github
    p, repo:maintainers, gh_event, read, auth-github
    p, repo:mainainers, gh_event, read, auth-github
    p, repo:members, gh_event, read, auth-github
    p, repo:collaborators, gh_event, read, auth-github
```

## Troubleshooting

### Token Validation Failures

1. **Check JWT signing key**: Ensure `client_secret` is correctly set
2. **Check token expiration**: Set `token_expiration` to appropriate value
3. **Verify clock sync**: Server clock must be synchronized for JWT validation

### Authorization Failures (403)

1. **Check Casbin model**: Verify request format matches `[request_definition]`
2. **Check policies**: Ensure policy rules match the request
3. **Check role assignments**: Verify `g` rules correctly assign users to roles
4. **Enable debug logging**: Add `log_level: debug` to see Casbin matching details

### Organization Restrictions

1. **Check `allowed_users` setting**: If set, user login must be explicitly listed
2. **Check `allowed_orgs` setting**: If set, user must belong to one of the allowed organizations
3. **Check `allow_when_no_restrictions`**: If both allowed_users and allowed_orgs are empty, this toggle controls whether login is allowed
4. **Verify OAuth scope**: Include `read:org` scope to read organization membership
5. **Check GitHub permissions**: Org membership might be private; user needs public membership

### Session Token Issues

1. **Token not in localStorage**: Check browser DevTools > Storage > Local Storage
2. **Bearer token malformed**: Header should be `Authorization: Bearer <token>`
3. **Expired token**: Implement token refresh logic (see Web UI integration)

## Production Checklist

- [ ] GitHub OAuth credentials stored securely (use environment variables)
- [ ] HTTPS enabled for all endpoints
- [ ] OAuth redirect URI matches GitHub App configuration exactly
- [ ] Casbin policies properly defined for your use case
- [ ] Token expiration set appropriately (24 hours recommended)
- [ ] Rate limiting enabled on auth endpoints
- [ ] Logs configured to track authentication events
- [ ] Backup and recovery plan for auth configuration
- [ ] Security audit of role assignments completed
- [ ] Team trained on policy management
