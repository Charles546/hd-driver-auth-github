# GitHub Authentication Driver for Honeydipper

This driver provides GitHub OAuth2-based authentication and authorization for Honeydipper's web UI and API. It integrates with Casbin for policy-based access control, allowing fine-grained permission management based on GitHub user identities and organizations.

## Features

- **GitHub OAuth2 Authentication**: Secure login via GitHub
- **User & Organization Support**: Authenticate based on GitHub username, organization membership, and team membership
- **Casbin Integration**: Policy-based access control with flexible role and permission definitions
- **Session Management**: JWT-based session tokens for web UI
- **User Info Caching**: Optional caching of GitHub user information to reduce API calls

## Installation

1. Clone this repository
2. Build the driver:
   ```bash
   cd cmd/hd-driver-auth-github
   go build -o hd-driver-auth-github
   ```
3. Place the binary in your Honeydipper installation path

## Configuration

The repository config in [config/init.yaml](/home/charles/code/hd-driver-auth-github/config/init.yaml) now uses a single entrypoint for both deployment modes:

- Default: download the driver from the named remote registry `charles-gh-pages`
- Optional: switch to a pre-fetched local binary by loading the repo with `options.use_local_binary: true`

Example repo entry:

```yaml
repos:
  - repo: https://github.com/Charles546/hd-driver-auth-github.git
    options:
      # Optional. Omit this line to use the registry-backed default.
      use_local_binary: true
```

Optional remote overrides can also be passed through repo options:

```yaml
repos:
  - repo: https://github.com/Charles546/hd-driver-auth-github.git
    options:
      registry: charles-gh-pages
      channel: stable
      # version: v0.1.0
```

### GitHub App Setup

Create a GitHub App or OAuth Application:

1. Go to https://github.com/settings/developers (for personal app or organization owner settings)
2. Create a new GitHub App or OAuth App
3. Set Authorization callback URL to: `https://your-domain/auth/github/callback`
4. Copy the Client ID and generate a Client Secret

### Honeydipper Configuration

Add the auth-github driver to your API daemon configuration:

```yaml
drivers:
  daemon:
    services:
      api:
        description: Honeydipper API service
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
                g2 = _, _
                g3 = _, _
                
                [policy_effect]
                e = some(where (p.eft == allow))
                
                [matchers]
                m = (r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.provider == p.provider) \
                  || (g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act && r.provider == p.provider) \
                  || (r.sub == p.sub && p.obj == 'everything' && r.act == p.act && r.provider == p.provider) \
                  || (p.sub == 'everyone' && r.obj == p.obj && r.act == p.act && r.provider == p.provider) \
                  || (r.sub == 'admin')
            policies:
              - |
                # Users get read access to webui
                p, user:github-username, webui, read, auth-github
                
                # Admins get write access
                p, admin-role, webui, write, auth-github
                
                # Define role memberships using g rules
                # g, github-username, admin-role
                
                # Organizations can be treated as role groups
                # g, github-username, org:my-org

            casbin-enforcer-options: {}

auth-github:
  data:
    client_id: ${GITHUB_CLIENT_ID}
    client_secret: ${GITHUB_CLIENT_SECRET}
    redirect_uri: https://your-domain/auth/github/callback

    # Optional: Usernames to restrict login to (case-insensitive)
    allowed_users: []
    
    # Optional: Organizations to restrict access to
    allowed_orgs: []

    # Optional: Controls behavior when allowed_users and allowed_orgs are both empty
    # true keeps legacy behavior (allow any authenticated GitHub user)
    # false requires explicit allowlists
    allow_when_no_restrictions: true
    
    # Optional: Teams within organizations (format: org:team)
    allowed_teams: []
    
    # Cache settings
    cache_ttl: 3600  # Cache user info for 1 hour
    cache_size: 1000  # Max users to cache
```

## Usage Examples

### Basic Policy Setup

Allow all authenticated GitHub users to read the web UI
(for strict mode, set allow_when_no_restrictions to false and configure allowed_users and/or allowed_orgs):

```yaml
policies:
  - |
    p, user:github-user, webui, read, auth-github
```

### Organization-Based Access

Grant access to users from specific organizations:

```yaml
policies:
  - |
    # Users in admin role can write
    p, admin-role, webui, write, auth-github
    
    # Members of "engineering" org are admins
    g, org:engineering, admin-role
    
    p, user:specific-username, webui, read, auth-github
```

### Role and Permission Hierarchy

```yaml
policies:
  - |
    # Permission hierarchy: write implies read
    p, viewer, webui, read, auth-github
    p, editor, webui, write, auth-github
    
    # User role assignments
    g, alice, editor
    g, bob, viewer
    g, charlie, editor
```

## How It Works

1. **Initial Authentication**:
   - User visits `/auth/github/login`
   - Driver redirects to GitHub OAuth
   - GitHub redirects back to `/auth/github/callback` with authorization code

2. **Token Exchange**:
   - Driver exchanges code for GitHub access token
   - Fetches user information from GitHub API
   - Creates JWT session token for web UI

3. **API Requests**:
   - Web UI sends requests with JWT in `Authorization: Bearer <token>` header
   - `authWebRequest` RPC handler validates JWT and extracts GitHub username
   - Casbin enforcer checks policies to authorize the request

4. **Authorization**:
   - Subject (GitHub username) is checked against Casbin policies
   - Request is allowed/denied based on policy rules
   - Supports hierarchical roles via Casbin role definition (g rules)

## Environment Variables

```
GITHUB_CLIENT_ID        - GitHub App/OAuth Client ID
GITHUB_CLIENT_SECRET    - GitHub App/OAuth Client Secret
AUTH_GITHUB_REDIRECT_URI - OAuth callback URL (optional, uses config default)
```

## Session Token Format

The driver generates JWT tokens containing:
- `sub` (subject): GitHub username
- `email`: GitHub user's email (if available)
- `iat` (issued at): Token creation time
- `exp` (expiration): Token expiration (default: 24 hours)
- `org` (organizations): List of GitHub organizations the user belongs to (if queried)

## Casbin Integration Details

The driver returns GitHub username as the subject, which is used in Casbin policies:

- **Direct user rules**: `p, username, object, action, auth-github`
- **Role assignments**: `g, username, role-name`
- **Organization groups**: `g, org:organization-name, role-name` (if enabled)

## Entitlement Derived Subjects

For routes configured with `entitlement_provider: auth-github`, the `check_entitlements` RPC returns a list of derived subjects based on GitHub access level to the requested target.

The target (`entitlementTarget`) can be:
- an organization slug, for example `honeydipper`
- a repository slug, for example `honeydipper/honeydipper`

The returned `derivedSubjects` always include the original target slug and add role subjects.

### Organization target output

For `entitlementTarget: honeydipper`, examples include:
- `honeydipper`
- `org:members`
- `org:collaborators`
- `org:maintainers`
- `org:owners`

Note: `org:mainainers` is also emitted as a compatibility alias for existing policy typos.

### Repository target output

For `entitlementTarget: honeydipper/honeydipper`, examples include:
- `honeydipper/honeydipper`
- `repo:members`
- `repo:collaborators`
- `repo:maintainers`
- `repo:owners`

Note: `repo:mainainers` is also emitted as a compatibility alias for existing policy typos.

### Casbin policy example

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

## Testing

```bash
go test ./...
```

## Commercial licensing

If your intended use does not fit AGPL obligations, see `LICENSE-COMMERCIAL.md` and contact the copyright holder for commercial terms.

## License

This project is prepared for dual licensing:

- `LICENSE` — GNU Affero General Public License v3.0
- `LICENSE-COMMERCIAL.md` — commercial licensing path for organizations that want to use the software outside the AGPL terms

The AGPL license applies by default unless you have a separate written commercial agreement with the copyright holder.

## Contributing

Contributions are welcome. Please ensure tests pass and add new tests for new features.

## References

- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [Casbin Documentation](https://casbin.org/)
- [Honeydipper Documentation](https://honeydipper.io/)
