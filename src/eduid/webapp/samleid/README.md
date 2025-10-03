# Samleid Application

This application combines the functionality of the previous `bankid` and `eidas` applications into a single unified `samleid` application.

## Overview

The `samleid` application provides SAML-based identity verification supporting multiple authentication methods:
- **BankID**: Swedish BankID authentication (uncertified-loa3)
- **Freja**: Freja eID authentication (loa3)
- **EIDAS**: European eID authentication (various LOA levels including eidas-low, eidas-sub, eidas-high, and their notified/non-notified variants)

## Architecture

### Key Components

1. **app.py**: Main application class `SamleidApp` that initializes the application with combined configuration
2. **settings/common.py**: Configuration supporting all LOA contexts from both bankid and eidas
3. **views.py**: Combined views handling verify-identity, verify-credential, and mfa-authenticate endpoints
4. **helpers.py**: Unified message types and helper functions
5. **proofing.py**: Combined proofing logic supporting:
   - `BankIDProofingFunctions`: NIN verification via BankID
   - `FrejaProofingFunctions`: NIN verification via Freja eID
   - `EidasProofingFunctions`: Foreign identity verification via EIDAS
6. **acs_actions.py**: SAML ACS (Assertion Consumer Service) actions for all methods
7. **saml_session_info.py**: Session information models for both NIN and Foreign eID

### Session Management

The application uses a dedicated session namespace `session.samleid` for storing SAML authentication state, consistent with the pattern used by other apps.

### LOA Support

The combined configuration supports all LOA (Level of Assurance) contexts:
- `uncertified-loa3`: BankID uncertified LOA3
- `loa1`, `loa2`, `loa3`, `loa4`: Sweden Connect LOA levels
- `eidas-low`, `eidas-sub`, `eidas-high`: EIDAS notified LOA levels
- `eidas-nf-low`, `eidas-nf-sub`, `eidas-nf-high`: EIDAS non-notified LOA levels

## Testing

Tests are adapted from the original bankid test suite and should work with all supported authentication methods. The test infrastructure includes:
- SAML configuration and test certificates
- Mock SAML responses for different scenarios
- Test cases covering identity verification, credential verification, and MFA authentication

## Migration Notes

When migrating from separate bankid/eidas deployments to samleid:
1. Update configuration to use `app_name: samleid`
2. Update SAML2 metadata endpoints to point to the new application
3. Session data will need to be migrated from `session.bankid` or `session.eidas` to `session.samleid`
4. Ensure all IdP configurations reference the correct entity ID for the samleid application
