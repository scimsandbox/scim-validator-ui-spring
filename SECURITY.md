# Security Policy

## Supported Versions

Security fixes are applied to:

- the current `main` branch
- the latest tagged release built from this repository

Older commits and local forks should not be assumed to receive backported
security fixes.

## Reporting a Vulnerability

Do not open public GitHub issues for security reports.

Use GitHub Security Advisories for private disclosure:

1. Open the repository Security tab.
2. Open Advisories.
3. Create a draft security advisory.
4. Include the affected route, class, workflow, or build path, along with
   reproduction steps, impact, and any mitigation you have identified.

If private reporting is unavailable, use the maintainer contact options listed
on GitHub.

## Scope of Security Review

The highest-risk areas in this repository are:

- Auth0 OIDC login, role mapping, and logout behavior in
  `src/main/java/de/palsoftware/scim/validator/ui/security`
- validator run inputs, because they include a target SCIM base URL and bearer
  token
- stored validation runs and captured HTTP exchanges, because they may contain
  sensitive payloads
- actuator exposure on port 9090
- Maven and Docker build paths that resolve the private `scim-validator`
  dependency

This repository does not contain the validator spec source code or the database
migrations. Secure the sibling `scim-validator` and `scim-validator-db`
repositories independently as well.

## Current Controls

The codebase currently includes these baseline controls:

- interactive login via Spring Security OAuth2 client and Auth0 OIDC
- role mapping from a configurable OIDC claim to `ROLE_ADMIN` and `ROLE_USER`
- CSRF protection for the web UI
- persistence of run metadata separately from the submitted bearer token itself

## Operational Guidance

If you deploy this app beyond a private sandbox, do all of the following first:

1. Replace all Auth0 settings, datasource credentials, and actuator keys with
   environment-specific secrets.
2. Put the UI behind HTTPS and a trusted reverse proxy.
3. Limit access to authenticated operators only. This is an admin surface, not
   a public application.
4. Treat stored validation runs and captured HTTP exchanges as sensitive data.
5. Protect `/actuator/**` separately and rotate the actuator API key when staff
   or environments change.
6. Use least-privileged database credentials and separate databases or schemas
   per environment.
7. Protect Maven settings used for GitHub Packages access, especially when
   building Docker images.

## Secrets Handling

- Do not commit Auth0 secrets, database passwords, actuator keys, or raw bearer
  tokens.
- Do not commit Maven settings that contain live GitHub Packages credentials.
- Do not reuse local sandbox values in shared or production environments.
- Assume any example values in documentation are placeholders only.

## Security Testing Expectations

When changing authentication, authorization, token handling, capture, stored
results, or dependency resolution, validate at least the relevant combination
of:

- the affected unit tests under `src/test/java/de/palsoftware/scim/validator/ui`
- a local `mvn clean verify`
- the changed UI flow manually in a local environment when appropriate

If your change affects stored schema assumptions or validator execution
contracts, also verify the change against the matching `scim-validator` and
`scim-validator-db` revisions.
