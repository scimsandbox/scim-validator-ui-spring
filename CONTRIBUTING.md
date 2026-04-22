# Contributing

Thanks for contributing to scim-validator-ui.

This repository is the validator UI and persistence layer. Keep changes focused
on the web app, its security model, validator run execution, stored results,
and documentation that matches the live repository structure.

## Ground Rules

- Keep each change narrow and intentional.
- Do not mix unrelated refactors into UI, workflow, or documentation changes.
- Do not commit bearer tokens, database credentials, Auth0 secrets, or machine-
  specific Maven settings.
- Update docs when runtime setup, dependency resolution, or security behavior changes.

## Before You Start

1. Check for existing issues or pull requests that already cover the same work.
2. Read [README.md](./README.md) before changing runtime behavior or setup.
3. If validator execution behavior changes, keep the UI code, docs, and the
   expected `scim-validator` version aligned.
4. If database expectations change, update the docs with the matching
   `scim-validator-db` assumptions.

## Local Setup

### Prerequisites

- JDK 25
- Maven 3.9+
- PostgreSQL
- an Auth0 application for interactive login testing
- access to the matching `scim-validator` jar, either from your local
  Maven repository or from GitHub Packages
- Docker if you want to build the container image locally

### Required runtime configuration

At minimum, set:

- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`
- `AUTH0_ISSUER_URI`
- `AUTH0_REDIRECT_URI`

Optional but commonly useful:

- `SERVER_PORT`
- `APP_SECURITY_OIDC_ROLE_CLAIM`
- `APP_SECURITY_OIDC_ADMIN_ROLE`
- `APP_SECURITY_OIDC_USER_ROLE`

### Database expectation

This repo validates an existing schema on startup. It does not create tables.

Before running locally, apply the migrations from `scim-validator-db` so the
database already contains `validator_mgmt_users`, `validation_run`,
`validation_test_result`, and `validation_http_exchange`.

### Validator dependency expectation

This repo executes spec classes from `de.palsoftware.scim:scim-validator` using
the published validator jar at runtime.

Before building locally, make sure Maven can resolve the matching version.

Typical options:

- install the sibling `scim-validator` repository locally
- or configure Maven access to GitHub Packages for `scimsandbox/scim-validator`

## Validation

Validate changes before opening a PR.

Common checks:

```bash
mvn clean verify
```

- if the scim-validator snapshot is not available locally, run
  `mvn install` in the `scim-validator` module first
- if you changed security or request handling, manually exercise the
  affected endpoint flow as well

## Code Areas

The main implementation areas are:

- `src/main/java/de/palsoftware/scim/validator/ui/controller`: UI routes
- `src/main/java/de/palsoftware/scim/validator/ui/service`: run execution and user provisioning
- `src/main/java/de/palsoftware/scim/validator/ui/security`: OIDC login, CSRF, logout, and actuator protection
- `src/main/java/de/palsoftware/scim/validator/ui/model` and `repo`: persistence model and data access
- `src/main/resources/templates` and `src/main/resources/static`: Thymeleaf UI and assets

## Project Conventions

Follow the existing patterns unless a refactor is explicitly part of the work:

- no Lombok
- prefer constructor injection
- DTOs may use Java records
- keep transactional boundaries deliberate
- keep validator-launcher and persistence behavior in the service layer rather
  than scattering it through controllers or templates

## If You Change These Areas

### Validator execution or result persistence

Review and update as needed:

- `ValidationRunService`
- the persisted model classes under `model`
- the corresponding views and tests
- `README.md` if setup or runtime behavior changes

### Authentication or authorization

Review and update as needed:

- `SecurityConfig`
- `AuthenticatedUser`
- shared helpers under `src/main/java/de/palsoftware/scim/validator/ui/security`
- `README.md` and `SECURITY.md`

### Docker or dependency resolution

Review and update as needed:

- `Dockerfile`
- `scripts/build-dev-image.sh`
- `scripts/push-dev-image.sh`
- the GitHub workflows
- `README.md`

## Pull Request Checklist

Before opening a PR, make sure it:

- explains what changed and why
- keeps unrelated edits out of scope
- updates docs if setup, security, or dependency expectations changed
- runs the relevant validation steps
- does not include secrets or machine-specific noise

## Reporting Bugs

When reporting a problem, include:

- whether the issue is in the UI, security flow, persistence layer, or validator execution
- the relevant route or class
- the database state or migration version if relevant
- the relevant Maven or runtime configuration with secrets removed
- reproduction steps, observed behavior, and any stack trace

## Security Issues

Do not report vulnerabilities through public issues.

Follow [SECURITY.md](./SECURITY.md) instead.
