from eduid.common.config.base import EduidEnvironment
from eduid.common.utils import get_short_hash
from eduid.queue.client import init_queue_item
from eduid.queue.db.message.payload import EduidVerificationEmail
from eduid.userdb import User
from eduid.userdb.logs import MailAddressProofing
from eduid.userdb.mail import MailAddress
from eduid.userdb.proofing import EmailProofingElement, EmailProofingState
from eduid.userdb.proofing.user import ProofingUser
from eduid.webapp.common.api.translation import get_user_locale
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.email.app import current_email_app as current_app


def new_proofing_state(email: str, user: User) -> EmailProofingState | None:
    old_state = current_app.proofing_statedb.get_state_by_eppn_and_email(user.eppn, email)
    current_app.logger.debug(f"Old proofing state in db: {old_state}")

    if old_state is not None:
        if old_state.is_throttled(current_app.conf.throttle_resend_seconds):
            return None
        current_app.proofing_statedb.remove_state(old_state)
        current_app.logger.info("Removed old proofing state")
        current_app.logger.debug(f"Old proofing state: {old_state.to_dict()}")

    verification = EmailProofingElement(email=email, verification_code=get_short_hash(), created_by="email")
    proofing_state = EmailProofingState(id=None, modified_ts=None, eppn=user.eppn, verification=verification)
    # XXX This should be an atomic transaction together with saving
    # the user and sending the letter.
    current_app.proofing_statedb.save(proofing_state, is_in_database=False)

    current_app.logger.info("Created new email proofing state")
    current_app.logger.debug(f"Proofing state: {proofing_state.to_dict()!r}.")

    return proofing_state


def send_verification_code(email: str, user: User) -> bool:
    state = new_proofing_state(email, user)
    if state is None:
        return False

    assert state.verification.verification_code  # please mypy
    payload = EduidVerificationEmail(
        email=email,
        verification_code=state.verification.verification_code,
        site_name=current_app.conf.eduid_site_name,
        language=get_user_locale() or current_app.conf.default_language,
        reference=state.reference,
    )

    message = init_queue_item(
        app_name=current_app.conf.app_name, expires_in=current_app.conf.email_verification_timeout, payload=payload
    )
    current_app.messagedb.save(message)
    current_app.logger.info(
        f"Saved verification email queue item in queue collection {current_app.messagedb._coll_name}"
    )
    current_app.logger.debug(f"email: {email}")
    if current_app.conf.environment == EduidEnvironment.dev:
        # Debug-log the code and message in development environment
        current_app.logger.debug(f"code: {state.verification.verification_code}")
        current_app.logger.debug(f"Generating verification e-mail with context:\n{payload}")
    current_app.logger.info(f"Sent email address verification mail to user {user} about address {email!s}.")
    return True


def verify_mail_address(state: EmailProofingState, proofing_user: ProofingUser) -> None:
    """
    :param proofing_user: ProofingUser
    :param state: E-mail proofing state

    :type proofing_user: eduid.userdb.proofing.ProofingUser
    :type state: EmailProofingState

    :return: None

    """
    email = proofing_user.mail_addresses.find(state.verification.email)
    if not email:
        email = MailAddress(email=state.verification.email, created_by="email", is_verified=True, is_primary=False)
        proofing_user.mail_addresses.add(email)
        # Adding the phone to the list creates a copy of the element, so we have to 'find' it again
        email = proofing_user.mail_addresses.find(state.verification.email)

    # please mypy, email should be set now
    assert email

    email.is_verified = True
    if not proofing_user.mail_addresses.primary:
        email.is_primary = True

    mail_address_proofing = MailAddressProofing(
        eppn=proofing_user.eppn,
        created_by="email",
        mail_address=email.email,
        reference=state.reference,
        proofing_version="2013v1",
    )
    if current_app.proofing_log.save(mail_address_proofing):
        save_and_sync_user(proofing_user)
        current_app.logger.info(f"Email address {state.verification.email!r} confirmed for user {proofing_user}")
        current_app.stats.count(name="email_verify_success", value=1)
        current_app.proofing_statedb.remove_state(state)
        current_app.logger.debug(f"Removed proofing state: {state}")
