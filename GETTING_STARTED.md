# GitHub Authentication Driver for Honeydipper

A complete, production-ready GitHub OAuth2 authentication driver for Honeydipper that integrates with Casbin for policy-based access control. Users can log in with their GitHub account, and administrators can define fine-grained access rules using Casbin policies and role definitions.

## 📋 Quick Start

### 1. GitHub App Setup
Create a GitHub OAuth App at https://github.com/settings/developers with:
- Authorization callback URL: `https://your-domain/auth/github/callback`
- Scopes: `user:email`, `read:org`

### 2. Build the Driver
```bash
cd hd-driver-auth-github
go build -o hd-driver-auth-github ./cmd/hd-driver-auth-github
```

### 3. Configure Honeydipper
```yaml
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

### 4. Define Casbin Policies
```yaml
policies:
  - |
    # Users get read access
    p, alice, webui, read, auth-github
    p, bob, webui, write, auth-github
    
    # Roles for organization members
    g, org:engineering, backend-team
    p, backend-team, webui, write, auth-github
```

## 📁 Repository Structure

```
hd-driver-auth-github/
├── cmd/hd-driver-auth-github/      # Driver implementation
│   ├── main.go                     # OAuth2 flow, JWT handling, RPC handlers
│   └── main_test.go                # Unit tests (5 tests, all passing)
├── config/                         # Configuration examples
│   ├── init.yaml                   # Default configuration template
│   ├── webui-example.yaml          # Web UI setup with role-based access
│   └── org-based-example.yaml      # Organization-based access control
├── docs/                           # Documentation
│   ├── INTEGRATION.md              # Complete web UI integration guide
│   └── DEVELOPMENT.md              # Developer guidelines
├── build/docker/                   # Docker configuration
│   └── Dockerfile                  # Multi-stage build
├── .github/workflows/              # CI/CD
│   └── tests.yml                   # Automated testing on push/PR
├── go.mod                          # Go module (1.26.1, 4 dependencies)
├── go.sum                          # Dependency checksums
├── README.md                       # Full project documentation
├── Makefile                        # Build targets
├── .gitignore                      # Git ignore patterns
├── LICENSE                         # GNU Affero General Public License v3.0
└── LICENSE-COMMERCIAL.md           # Commercial licensing notice
```

## 🔑 Key Features

### GitHub OAuth2 Integration
- Secure OAuth2 code-to-token exchange
- Automatic user info fetching from GitHub API
- Optional organization membership validation
- Optional team-based restrictions

### JWT Session Tokens
- HS256 signed with OAuth client secret
- Contains: username, email, GitHub ID, organizations (optional)
- Configurable expiration (default: 24 hours)
- Email verification built-in

### Casbin Authorization
- Direct user-based rules: `p, username, object, action, auth-github`
- Role-based access control: `g, user, role` + `p, role, object, action, auth-github`
- Organization membership roles: `g, org:org-name, role`
- Admin override: `p, admin, everything, write, auth-github`
- Permission inheritance: read actions satisfy write policies

### Performance & Reliability
- User information caching (1 hour TTL, 1000 users default)
- Reduces GitHub API calls significantly
- Configurable cache parameters
- Race-safe token validation
- Robust error handling and logging

## 📚 Documentation

- **[README.md](README.md)** - Project overview and features
- **[docs/INTEGRATION.md](docs/INTEGRATION.md)** - Complete web UI integration guide with code examples
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** - Developer guide for extending the driver
- **[config/init.yaml](config/init.yaml)** - Single configuration template for both registry download (default) and local binary mode via repo options
- **[config/webui-example.yaml](config/webui-example.yaml)** - Web UI example with role-based access
- **[config/org-based-example.yaml](config/org-based-example.yaml)** - Organization-based access control example

## 🧪 Testing

All tests pass with 100% coverage of token creation, validation, and expiration scenarios:

```bash
# Run all tests
go test -v ./...

# Run with race detector
go test -race ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Test Results** (5/5 passing):
- ✅ `TestCreateSessionToken` - JWT creation with proper claims
- ✅ `TestVerifyAndExtractToken` - Token validation and subject extraction
- ✅ `TestVerifyAndExtractTokenExpired` - Expired token detection
- ✅ `TestVerifyAndExtractTokenInvalid` - Invalid token format handling
- ✅ `TestGenerateStateToken` - OAuth state token uniqueness

## 🚀 Deployment

### Docker Build
```bash
docker build -f build/docker/Dockerfile -t hd-driver-auth-github:latest .
docker run --rm -e GITHUB_CLIENT_ID=xxx -e GITHUB_CLIENT_SECRET=yyy \
  hd-driver-auth-github api
```

### Binary Build
```bash
make build
# Output: ./hd-driver-auth-github
```

### Integration
Place the binary in your Honeydipper drivers directory and reference in config.

## 📞 Configuration Reference

### Required Settings
- `client_id` - GitHub OAuth Client ID (or `GITHUB_CLIENT_ID` env var)
- `client_secret` - GitHub OAuth Client Secret (or `GITHUB_CLIENT_SECRET` env var)
- `redirect_uri` - OAuth callback URL (must match GitHub App config exactly)

### Optional Settings
- `allowed_users` - List of GitHub usernames to restrict access (case-insensitive)
- `allowed_orgs` - List of GitHub organizations to restrict access
- `allow_when_no_restrictions` - Allows login when both allowed_users and allowed_orgs are empty (default: true)
- `allowed_teams` - List of teams as `org:team` for finer-grained restrictions
- `token_expiration` - JWT lifetime in seconds (default: 86400 = 24 hours)
- `cache_ttl` - User info cache lifetime in seconds (default: 3600 = 1 hour)
- `cache_size` - Maximum number of cached users (default: 1000)

## 🔐 Security Considerations

1. **Credentials**: Store `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in secure environment variables
2. **HTTPS**: Always use HTTPS in production; OAuth requires secure callbacks
3. **Token Scope**: Requests `user:email` and `read:org` scopes only
4. **Login Restrictions**: Use `allowed_users` and/or `allowed_orgs` to limit who can authenticate
5. **Token Expiration**: Set reasonable expiration; users re-authenticate when expired
6. **Casbin Policies**: Regularly audit role definitions and policy assignments

## 🤝 Integration Example

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for complete examples including:

1. GitHub OAuth App setup (step-by-step)
2. Honeydipper configuration with Casbin models  
3. Web UI components for login flow
4. API request authentication with JWT
5. Policy examples (users, roles, organizations, hierarchy)
6. Troubleshooting guide

## 📝 License

This project is prepared for dual licensing:

- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — commercial licensing path for organizations that want to use the software outside the AGPL terms

The AGPL license applies by default unless you have a separate written commercial agreement with the copyright holder.

## 🛠️ Technology Stack

- **Language**: Go 1.26.1
- **OAuth2**: `golang.org/x/oauth2` with GitHub endpoint
- **JWT**: `github.com/golang-jwt/jwt/v5` with HS256 signing
- **Framework**: Honeydipper v4.0.0+ (pkg/dipper)
- **Authorization**: Casbin model-based policies
- **Testing**: Go standard testing with comprehensive test cases

## 🎯 Use Cases

- 🔓 **GitHub-based login** for web UI and API
- 👥 **Organization-based access control** for enterprise deployments
- 👨‍💼 **Role-based access control** with Casbin policies
- 🔐 **Fine-grained permissions** per user or group
- 🏢 **Multi-organization support** with team restrictions
- 📊 **Audit trail** through Honeydipper logging

---

For issues, questions, or contributions, please refer to the [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) guide.
