"""
Static conformance check for the ProofingApp protocol.

`current_proofing_app` is a `cast`, so type checkers never relate a real app to the protocol. The functions below
assign each proofing app to ProofingApp, so `make typecheck` (mypy and ty) fails if an app stops satisfying it.
"""

import re
from pathlib import Path

from eduid.webapp.bankid.app import BankIDApp
from eduid.webapp.common.proofing.app import ProofingApp
from eduid.webapp.eidas.app import EidasApp
from eduid.webapp.freja_eid.app import FrejaEIDApp
from eduid.webapp.samleid.app import SamlEidApp
from eduid.webapp.svipe_id.app import SvipeIdApp


def _eidas(app: EidasApp) -> ProofingApp:
    return app


def _bankid(app: BankIDApp) -> ProofingApp:
    return app


def _samleid(app: SamlEidApp) -> ProofingApp:
    return app


def _freja_eid(app: FrejaEIDApp) -> ProofingApp:
    return app


def _svipe_id(app: SvipeIdApp) -> ProofingApp:
    return app


def test_proofing_apps_conform_to_protocol() -> None:
    # The assertions are static (see the functions above). This keeps the module collected and the imports checked.
    assert all((_eidas, _bankid, _samleid, _freja_eid, _svipe_id))


# Known tech debt: these modules still import document user info models from other webapps.
# Move the models to common and remove the entries; do not add new ones.
_KNOWN_WEBAPP_IMPORTS = {"methods.py", "mfa_signup.py", "shared_actions.py"}


def test_shared_proofing_code_imports_no_webapp_modules() -> None:
    """common/proofing must stay app-agnostic (see ProofingApp)."""
    proofing_dir = Path(__file__).parent.parent
    pattern = re.compile(r"^(?:from|import) eduid\.webapp\.(?!common\b)[a-z_]+", re.MULTILINE)
    offenders = {p.name for p in proofing_dir.glob("*.py") if pattern.search(p.read_text())}
    assert offenders <= _KNOWN_WEBAPP_IMPORTS, (
        f"new webapp imports in common/proofing: {offenders - _KNOWN_WEBAPP_IMPORTS}"
    )
