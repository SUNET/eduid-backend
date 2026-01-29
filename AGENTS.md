# AGENTS.md - AI Agent Guidelines for eduID Backend

This document provides guidelines for AI coding agents working in the eduID Backend repository.

## Project Overview

eduID Backend is a Python 3.13 monorepo for Swedish federated identity management:
- **Flask web apps** (identity proofing, authentication, user management)
- **FastAPI APIs** (SCIM, MACC)
- **Celery workers** (background tasks)
- **SATOSA plugins** (SAML/OIDC proxy)

Key technologies: Flask, FastAPI, Pydantic v2, MongoDB, Neo4j, Redis, Celery, SAML2, WebAuthn/FIDO2.

## Build/Lint/Test Commands

### Running Tests

```bash
# Run all tests
make test

# Run a single test file
PYTHONPATH=src pytest -vvv src/eduid/webapp/freja_eid/tests/test_app.py

# Run a specific test class
PYTHONPATH=src pytest -vvv src/eduid/webapp/freja_eid/tests/test_app.py::FrejaEIDTests

# Run a specific test method
PYTHONPATH=src pytest -vvv src/eduid/webapp/freja_eid/tests/test_app.py::FrejaEIDTests::test_app_starts

# Run tests matching a pattern
PYTHONPATH=src pytest -vvv -k "test_verify" src/eduid/webapp/freja_eid/tests/
```

Tests require Docker services (MongoDB, Redis, Neo4j, SMTP). Tests auto-start containers as needed.

### Linting and Formatting

```bash
make lint       # Run ruff linter
make reformat   # Fix imports + format code + extended checks
```

### Type Checking

**Run both type checkers before submitting changes:**

```bash
# mypy (required)
make typecheck

# ty - experimental type checker (required, run with venv activated)
uvx ty check
```

- **mypy**: Uses plugins `pydantic.mypy`, `marshmallow_dataclass.mypy`
- **ty** (experimental): New type checker being evaluated in beta
  - Configuration in [ty.toml](ty.toml)
  - Requires virtual environment to be activated first

## Code Style Guidelines

### Import Ordering

Imports are organized in groups separated by blank lines:
1. `from __future__ import annotations` (if needed)
2. Standard library imports (alphabetically)
3. Third-party imports (alphabetically)
4. Local project imports (alphabetically)

```python
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, Field

from eduid.userdb.user import User
from eduid.webapp.common.api.messages import TranslatableMsg
```

### Type Annotations

Use modern Python 3.10+ type syntax:

```python
def get_user(identifier: str) -> User | None:            # Union with |
def require_user[T](f: Callable[..., T]) -> Callable[..., T]:  # Generic params
def process(items: Sequence[str]) -> Mapping[str, Any]:  # collections.abc types
```

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Classes | PascalCase | `UserPreferences`, `FrejaEIDApp` |
| Functions/methods | snake_case | `get_user`, `verify_identity` |
| Private members | Leading underscore | `_parse_data`, `_internal_state` |
| Constants | SCREAMING_SNAKE_CASE | `EPPN_LENGTH = 11` |
| Module variables | snake_case | `logger = logging.getLogger(__name__)` |

### Pydantic Models

```python
class UserConfig(BaseModel):
    name: str = Field(alias="displayName")
    email: str | None = Field(default=None)
    
    model_config = ConfigDict(populate_by_name=True, validate_assignment=True, extra="forbid")
```

### Error Handling

Use hierarchical custom exceptions:
```python
class EduIDDBError(Exception):
    def __init__(self, reason: object) -> None:
        Exception.__init__(self)
        self.reason = reason

class UserDoesNotExist(EduIDDBError):
    """Requested user could not be found."""
```

### Logging

```python
logger = logging.getLogger(__name__)
logger.debug(f"Processing user: {user.eppn}")
current_app.logger.exception("Unexpected error")  # In Flask views
```

### Docstrings (Sphinx/reST style)

```python
def authenticate(self, user_id: str, factors: Sequence[VCCSFactor]) -> bool:
    """
    Authenticate a user with the provided factors.

    :param user_id: Persistent user identifier
    :param factors: Authentication factors to verify
    :returns: True if authentication succeeds
    """
```

### Enums

```python
from enum import StrEnum, unique

@unique
class IdentityType(StrEnum):
    NIN = "nin"
    EIDAS = "eidas"
    FREJA = "freja"
```

### Flask Views

```python
@blueprint.route("/verify", methods=["POST"])
@UnmarshalWith(RequestSchema)
@MarshalWith(ResponseSchema)
@require_user
def verify(user: User, method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    ...
    return success_response(payload={"status": "ok"})
```

## Testing Patterns

Tests are located alongside source code in `tests/` subdirectories:
```
src/eduid/webapp/freja_eid/
├── app.py
├── views.py
└── tests/
    └── test_app.py
```

### Base Test Classes

Each webapp has a specific test base class. For the IdP, use `IdPAPITests`:

```python
from eduid.webapp.idp.tests.test_api import IdPAPITests

class TestMyFeature(IdPAPITests):
    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return super().update_config(config)

    def test_something(self) -> None:
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        # ... test logic
```

For other webapps, use `EduidAPITestCase[AppType]`:

```python
class MyAppTests(EduidAPITestCase[MyApp]):
    def load_app(self, config: dict[str, Any]) -> MyApp:
        return my_app_init_app(name="testing", config=config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config["my_setting"] = "test_value"
        return config
```

### Test Helper Methods (IdP)

The `IdPAPITests` base class provides helper methods for common test scenarios:

```python
# Add a security key (FIDO/WebAuthn credential) to test user
self.add_test_user_security_key(
    user=None,                      # defaults to self.test_user
    credential_id="webauthn_keyhandle",
    is_verified=False,
    mfa_approved=False,
    always_use_security_key=True,
)

# Add external MFA credential (SwedenConnect, eIDAS, BankID, Freja)
from eduid.userdb.credentials.external import TrustFramework
cred = self.add_test_user_external_mfa_cred(
    user=None,                           # defaults to self.test_user
    trust_framework=TrustFramework.SWECONN,  # SWECONN, EIDAS, BANKID, FREJA
    trust_level="loa3",                  # e.g., "loa3", "eidas-nf-high", "uncertified-loa3", "freja-loa3"
)

# Add Terms of Use acceptance
self.add_test_user_tou(eppn=None, version=None)

# Add mail address
self.add_test_user_mail_address(mail_address)

# Get user from IdP userdb
user = self.app.userdb.lookup_user(self.test_user.eppn)
```

### Mocking Patterns

When mocking complex objects, use `cast()` for proper typing:

```python
from typing import cast
from unittest.mock import MagicMock

def _make_ticket(self, credentials_used: Mapping[ElementKey, AuthnData] | None = None) -> LoginContext:
    if credentials_used is None:
        credentials_used = {}
    ticket = MagicMock(spec=LoginContext)
    ticket.pending_request = MagicMock()
    ticket.pending_request.credentials_used = credentials_used
    return cast(LoginContext, ticket)
```

Use real objects instead of mocks when feasible:

```python
# Prefer real AuthnData over MagicMock
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.common.misc.timeutil import utc_now

authn_data = AuthnData(cred_id=credential.key, timestamp=utc_now())
```

### Post-Edit Checklist

After completing test changes, always run:

```bash
make reformat   # Fix imports and formatting
make typecheck  # Verify type correctness
```

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(webapp): add new identity verification flow
fix(userdb): handle missing email gracefully
refactor(scimapi): simplify group membership logic
test(workers): add coverage for edge cases
docs: update API documentation
chore: update dependencies
```

## Project Structure

```
src/eduid/
├── common/       # Shared utilities, config, models
├── graphdb/      # Neo4j integration
├── maccapi/      # MACC API (FastAPI)
├── queue/        # Celery message queue
├── satosa/       # SATOSA proxy plugins
├── scimapi/      # SCIM 2.0 API (FastAPI)
├── userdb/       # User database models
├── vccs/         # Credential validation
├── webapp/       # Flask web applications
└── workers/      # Background workers
```

## Ruff Configuration

- Line length: 120 characters
- Target: Python 3.13
- Key rules: ANN, ASYNC, E, F, I (isort), PERF, UP (pyupgrade)
- Magic numbers allowed in test files (PLR2004 ignored)

## CI/CD

GitHub Actions runs on push/PR:
1. **unittests**: `make test` with Docker services
2. **typecheck**: `make typecheck` (mypy)
3. **lint**: ruff linting

All three must pass for merge.
