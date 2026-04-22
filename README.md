# SCIM Sandbox - Validator UI Spring

This repository contains the Spring Boot UI for running the standalone
`scim-validator` suite and storing the results in a PostgreSQL database.

## What This Repo Contains

- a server-side rendered Thymeleaf UI for creating validation runs
- persistence for validator users, runs, per-test results, and captured HTTP
  exchanges
- Auth0 OIDC login, role mapping, CSRF protection, and an actuator API-key
  filter
- a JUnit Platform launcher integration that executes the A1-A9 validator specs
  from `scim-validator`
- a Dockerfile and GitHub Actions workflows for build, release, and image
  publishing

## What This Repo Does Not Contain

- the SCIM provider implementation you validate against
- the validator spec source code or bootstrap logic
- the database migrations for `validator_mgmt_users`, `validation_run`,
  `validation_test_result`, or `validation_http_exchange`
- Docker Compose, Kubernetes manifests, or the old multi-module reactor layout

## Features

- create named validation runs against a target SCIM base URL and bearer token
- execute the validator suite from the UI
- persist run summaries, per-test outcomes, and HTTP exchanges
- browse historical runs and inspect request/response details
- delete stored runs and their associated results
- protect `/actuator/**` with `X-API-KEY`

## Routes

| Area | Routes |
| --- | --- |
| UI | `/`, `/runs/{runId}` |
| Run actions | `POST /runs`, `POST /runs/{runId}/delete` |
| Auth | `POST /logout` |
| Actuator | `GET /actuator/health` with `X-API-KEY` |

## Repository Layout

```text
.
├── Dockerfile
├── pom.xml
├── scripts
│   ├── build-dev-image.sh
│   └── push-dev-image.sh
└── src
    ├── main
    │   ├── java
    │   │   └── de/palsoftware/scim/validator/ui
    │   │       ├── controller
    │   │       ├── dto
    │   │       ├── model
    │   │       ├── repo
    │   │       ├── security
    │   │       └── service
    │   └── resources
    │       ├── application.yml
    │       ├── static
    │       └── templates
    └── test
        └── java
            └── de/palsoftware/scim/validator/ui
```

## Runtime Notes

- Java: 25
- Spring Boot: 3.5.14
- Database: PostgreSQL
- Templating: Thymeleaf
- Security: Spring Security OAuth2 client with Auth0 OIDC
- Persistence: Spring Data JPA
- Default port: `8082`

The application uses `spring.jpa.hibernate.ddl-auto=validate`, so it expects
an existing schema and will not create tables on startup.

## Dependency and Schema Expectations

This app depends on two sibling repositories:

- `scim-validator` provides the validator suite classes that are executed at
  runtime from the published validator jar.
- `scim-validator-db` provides the PostgreSQL schema this app validates on
  startup and writes to at runtime.

Before building or running this app, make sure both of the following are true:

1. your target database has already been migrated with `scim-validator-db`
2. Maven can resolve `de.palsoftware.scim:scim-validator:${project.version}`

For local development, that usually means either:

- installing the matching `scim-validator` version into your local Maven repo
- or configuring Maven access to GitHub Packages for `scimsandbox/scim-validator`

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `SPRING_DATASOURCE_URL` | yes | PostgreSQL JDBC URL |
| `SPRING_DATASOURCE_USERNAME` | yes | PostgreSQL username |
| `SPRING_DATASOURCE_PASSWORD` | yes | PostgreSQL password |
| `AUTH0_CLIENT_ID` | yes | Auth0 OIDC client ID |
| `AUTH0_CLIENT_SECRET` | yes | Auth0 OIDC client secret |
| `AUTH0_ISSUER_URI` | yes | Auth0 issuer URI |
| `AUTH0_REDIRECT_URI` | yes | OAuth redirect URI used by Spring Security |
| `APP_SECURITY_OIDC_ROLE_CLAIM` | no | Claim used to extract roles. Default: `https://scimplayground.dev/roles` |
| `APP_SECURITY_OIDC_ADMIN_ROLE` | no | Role value mapped to `ROLE_ADMIN`. Default: `admin` |
| `APP_SECURITY_OIDC_USER_ROLE` | no | Role value mapped to `ROLE_USER`. Default: `user` |
| `SERVER_PORT` | no | Spring Boot server port. Default: `8082` |

## Running Locally

### 1. Prepare the database

Apply the migrations from `scim-validator-db` to a PostgreSQL database.

### 2. Export configuration

```bash
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/scim_validator
export SPRING_DATASOURCE_USERNAME=scim
export SPRING_DATASOURCE_PASSWORD=scim
export AUTH0_CLIENT_ID=your-auth0-client-id
export AUTH0_CLIENT_SECRET=your-auth0-client-secret
export AUTH0_ISSUER_URI=https://your-tenant.us.auth0.com/
export AUTH0_REDIRECT_URI=http://localhost:8082/login/oauth2/code/auth0
```

### 3. Start the app

```bash
mvn spring-boot:run
```

### 4. Check health

```bash
curl http://localhost:8082/actuator/health
```

## Building

```bash
mvn clean package
```

The packaged JAR is written to `target/`.

## Testing

```bash
mvn clean verify
```

If Maven cannot resolve the matching `scim-validator` test-jar dependency,
install the sibling repository first or configure Maven access to GitHub
Packages.

## Docker

The Docker build needs Maven settings so the image build can resolve the
private `scim-validator` dependency. Use the helper script:

```bash
./scripts/build-dev-image.sh
```

If you want to publish the local dev image to Docker Hub, push it with:

```bash
./scripts/push-dev-image.sh
```

Or run Docker BuildKit directly with secrets:

```bash
DOCKER_BUILDKIT=1 docker build \
  --secret id=maven_settings,src="$HOME/.m2/settings.xml" \
  --secret id=maven_security,src="$HOME/.m2/settings-security.xml" \
  -t scim-validator-ui:dev \
  .
```

Run the container:

```bash
docker run --rm \
  -p 8082:8082 \
  -e SERVER_PORT=8082 \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://host.docker.internal:5432/scim_validator \
  -e SPRING_DATASOURCE_USERNAME=scim \
  -e SPRING_DATASOURCE_PASSWORD=scim \
  -e AUTH0_CLIENT_ID=your-auth0-client-id \
  -e AUTH0_CLIENT_SECRET=your-auth0-client-secret \
  -e AUTH0_ISSUER_URI=https://your-tenant.us.auth0.com/ \
  -e AUTH0_REDIRECT_URI=http://localhost:8082/login/oauth2/code/auth0 \
  scim-validator-ui:dev
```

## Versioning

The working version lives in `pom.xml`. The manual release workflow runs from
`main`, uses the Maven Release Plugin to publish the current `-SNAPSHOT`
version as `vX.Y.Z`, and creates the GitHub release. Publishing that GitHub
release triggers the Docker publish workflow for `edipal/scim-validator-ui`.

## Development Notes

- `ValidationController` owns the UI flow for creating, viewing, and deleting
  runs
- `ValidationRunService` launches the suite and persists run/test/exchange data
- `SecurityConfig` configures OIDC login, logout, CSRF, and the actuator API-key filter
- `src/main/resources/templates` contains the Thymeleaf UI

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md).
