# Development Guide

## Building the Driver

### Prerequisites

- Go 1.26 or later
- Git

### Local Build

```bash
cd hd-driver-auth-github
go mod download
go build -o hd-driver-auth-github ./cmd/hd-driver-auth-github
```

The binary `hd-driver-auth-github` can now be copied to your Honeydipper installation.

### Docker Build

```bash
docker build -f build/docker/Dockerfile -t hd-driver-auth-github:latest .
docker run --rm -e GITHUB_CLIENT_ID=... -e GITHUB_CLIENT_SECRET=... \
  hd-driver-auth-github api
```

## Testing

### Run All Tests

```bash
go test -v -race ./...
```

### Run Specific Tests

```bash
go test -v -race -run TestCreateSessionToken ./cmd/hd-driver-auth-github/
```

### Coverage Report

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Project Structure

```
hd-driver-auth-github/
├── cmd/
│   └── hd-driver-auth-github/
│       ├── main.go              # Driver entry point, OAuth2 flow
│       └── main_test.go         # Unit tests
├── config/
│   ├── init.yaml                # Default configuration
│   ├── webui-example.yaml       # Web UI example with roles
│   └── org-based-example.yaml   # Org-based access control example
├── docs/
│   └── INTEGRATION.md           # Web UI integration guide
├── build/
│   └── docker/
│       └── Dockerfile           # Docker build configuration
├── go.mod                       # Go module definition
├── LICENSE                      # GNU Affero General Public License v3.0
├── LICENSE-COMMERCIAL.md        # Commercial licensing notice
├── README.md                    # Project documentation
├── Makefile                     # Build targets
└── .gitignore                   # Git ignore patterns
```

## Key Components

### main.go

**Driver Initialization** (`main()`)
- Parses command-line arguments
- Creates new `authGitHubDriver`
- Registers RPC handlers
- Calls `driver.Run()` to start

**Configuration** (`initConfig()`)
- Loads GitHub OAuth credentials (from config or environment)
- Initializes Casbin enforcer options
- Sets up JWT signing key
- Configures organization restrictions

**Request Handlers**
- `authWebRequest()`: Validates JWT bearer tokens for API requests
- `githubOAuthCallback()`: Handles OAuth callback with authorization code

**GitHub API Integration**
- `getGitHubUser()`: Fetches authenticated user info
- `getUserOrganizations()`: Gets user's organizations

**Token Management**
- `createSessionToken()`: Creates JWT with user claims
- `verifyAndExtractToken()`: Validates and extracts subject from JWT

## Common Tasks

### Add a New Configuration Option

1. Parse in `initConfig()`:
```go
if myOption, ok := dipper.GetMapDataStr(d.Options, "data.my_option"); ok {
    d.MyOption = myOption
}
```

2. Document in `config/init.yaml`

3. Update README.md

### Add a New RPC Handler

1. Register in `main()`:
```go
driver.RPCHandlers["my_new_handler"] = driver.myNewHandler
```

2. Implement handler:
```go
func (d *authGitHubDriver) myNewHandler(m *dipper.Message) {
    // Implementation
    m.Reply <- dipper.Message{Payload: result}
}
```

3. Add tests

### Modify JWT Claims

Update the `SessionToken` struct:
```go
type SessionToken struct {
    Subject string       `json:"sub"`
    Email   string       `json:"email"`
    MyField string       `json:"my_field"`  // New field
    // ...
}
```

Update token creation in `createSessionToken()` to populate new fields.

## Debugging

### Enable Verbose Logging

In Honeydipper configuration:
```yaml
drivers:
  daemon:
    services:
      api:
        log_level: debug
```

### Test Token Generation Locally

```bash
go run ./cmd/hd-driver-auth-github -test-create-token
```

### Inspect JWT Token

Use online decoder at https://jwt.io/ or command-line:
```bash
echo $TOKEN | jq -R 'split(".") | .[1] | @base64d | fromjson'
```

### Mock GitHub API Responses

The tests use standard mock patterns. To add a new test:
```go
func TestMyFeature(t *testing.T) {
    driver := &authGitHubDriver{
        jwtSigningKey: []byte("test-key..."),
        // ...
    }
    
    // Test implementation
}
```

## Performance Considerations

### User Cache

Reduces GitHub API calls by caching user info:
- Default: 1000 users, 1 hour TTL
- Configurable in `data.cache_ttl` and `data.cache_size`

To increase cache:
```yaml
auth-github:
  data:
    cache_ttl: 7200      # 2 hours
    cache_size: 5000     # More users
```

### JWT Token Size

Token size grows with each claim. Keep claims minimal:
- Basic: ~200 bytes
- With organizations: ~300 bytes

### GitHub API Rate Limits

- Unauthenticated: 60 requests/hour per IP
- Authenticated: 5000 requests/hour per user

The driver uses bearer token authentication, so you get the higher limit.

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes and add tests
4. Run: `go test -v -race ./...`
5. Run: `go fmt ./...`
6. Commit with clear message
7. Push to branch
8. Create Pull Request

## Release Process

1. Update version in `go.mod` and `README.md`
2. Update `CHANGELOG.md` with changes
3. Create git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. Build binary: `go build -o hd-driver-auth-github ./cmd/hd-driver-auth-github`
6. Create GitHub Release with binary attachment

## License

This project is prepared for dual licensing:

- [LICENSE](../LICENSE) — GNU Affero General Public License v3.0
- [LICENSE-COMMERCIAL.md](../LICENSE-COMMERCIAL.md) — commercial licensing path for organizations that want to use the software outside the AGPL terms

The AGPL license applies by default unless you have a separate written commercial agreement with the copyright holder.
