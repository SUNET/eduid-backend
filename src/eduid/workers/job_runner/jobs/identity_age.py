from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from dateutil.relativedelta import relativedelta

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.queue.db.message.payload import (
    EduidIdentityExpiryWarningEmail,
    EduidIdentityUnverifiedEmail,
    EmailPayload,
)
from eduid.userdb.exceptions import UserDoesNotExist, UserOutOfSync
from eduid.userdb.identity import (
    IdentityAgeStatus,
    IdentityElement,
    IdentityList,
    IdentityType,
    get_identity_age_status,
    identity_expires_at,
)
from eduid.userdb.identity_age.db import IdentityAgeNotification, IdentityAgeNotificationDB
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.workers.job_runner.context import Context
from eduid.workers.job_runner.helpers import save_and_sync_user, send_mail_to_user


@dataclass(frozen=True)
class _Limits:
    """Time limits for the job, derived from configuration."""

    now: datetime
    max_age: relativedelta
    warning_period: relativedelta
    min_notice: timedelta


def _limits(context: Context) -> _Limits:
    config = context.config.identity_age
    return _Limits(
        now=utc_now(),
        max_age=relativedelta(years=config.max_age_years),
        warning_period=relativedelta(months=config.warning_period_months),
        min_notice=timedelta(days=config.min_notice_days),
    )


def _gather_cutoff(now: datetime, max_age_years: int, warning_period_months: int) -> datetime:
    """
    Latest verification time for which an identity can already need action (be in the warning window or expired).

    The exact rule (get_identity_age_status) uses calendar arithmetic: an identity verified at v needs action when
    now >= v + max_age_years - warning_period_months. That is not invertible at month ends (relativedelta clamps
    the day), so now - max_age + warning_period can be earlier than v for an identity that needs action.

    Instead use fixed-length bounds that are never earlier than the exact one. A year is at least 365 days, so
    v + years >= v + 365 * years days. A month is at most 31 days, so subtracting months removes at most
    31 * months days. Hence v + 365 * years days - 31 * months days <= exact action time <= now, which gives
    v <= now - 365 * years days + 31 * months days. This is monotonic in both parameters and always >= the exact
    cutoff, so it can only over-match. Over-matching is fine: _needs_action applies the exact rules per identity.
    """
    return now - timedelta(days=365 * max_age_years) + timedelta(days=31 * warning_period_months)


def _notification_db(context: Context) -> IdentityAgeNotificationDB:
    """
    The notification database to use: a dry run reads and writes only its own separate collection and never
    touches the real one, a real run never touches the dry run collection.
    """
    return context.identity_age_dry_run_db if context.dry_run else context.identity_age_db


def _needs_action(
    context: Context, eppn: str, identities: IdentityList, limits: _Limits, has_verified_mail: bool
) -> bool:
    """
    Cheap check used when gathering: does any configured identity type have an identity that is in the warning
    window or past the maximum age, and for which something is still left to do?

    An identity in the warning window only needs action if the user has a verified mail address to warn, otherwise
    the user would be queued and found to have nothing to do on every run. An expired identity always needs
    action (without a verified mail address it is unverified right away).

    The real decisions are made in _check_user.
    """
    config = context.config.identity_age
    for identity in identities.verified:
        if not isinstance(identity, IdentityElement) or identity.identity_type not in config.identity_types:
            continue
        status = get_identity_age_status(identity, limits.now, limits.max_age, limits.warning_period)
        if status not in (IdentityAgeStatus.WARN, IdentityAgeStatus.EXPIRED):
            continue
        if status is IdentityAgeStatus.WARN and not has_verified_mail:
            continue
        verified_at = identity.verified_at
        if verified_at is None:
            continue
        notification = _notification_db(context).get(eppn, identity.identity_type, verified_at)
        if notification is not None:
            if notification.unverified_ts is not None:
                continue
            warned_at = notification.warning_sent_ts
            # An expired identity of a user without a verified mail address is unverified right away (see
            # _check_user), so only wait for the notice period if there is someone to give notice to.
            waiting_for_notice = status is IdentityAgeStatus.EXPIRED and has_verified_mail
            if warned_at is not None and (
                status is IdentityAgeStatus.WARN or (waiting_for_notice and warned_at + limits.min_notice > limits.now)
            ):
                # Already warned and nothing more to do until the notice period has passed
                continue
        return True
    return False


def gather_identity_age_users(context: Context) -> None:
    """
    Gather and queue all users with a verified identity that is in the warning window or past the maximum age.

    Users already in the queue are skipped. The queued users are handled one at a time by process_identity_age_users.

    In dry run mode users are queued as usual (the queue is shared with real runs), but the decision whether a user
    needs action is based on the dry run notification records, not the real ones.
    """
    config = context.config.identity_age
    limits = _limits(context)
    context.logger.debug("gathering users with identities to check the age of")

    # Only users that may have an identity in or past the warning window are matched.
    projection = {"eduPersonPrincipalName": 1, "identities": 1, "mailAliases": 1}
    verified_before = _gather_cutoff(limits.now, config.max_age_years, config.warning_period_months)
    queued_count = 0
    skipped_count = 0
    for doc in context.central_db.iter_unterminated_users_with_verified_identity(
        identity_types=config.identity_types, projection=projection, verified_before=verified_before
    ):
        eppn = doc["eduPersonPrincipalName"]
        try:
            identities = IdentityList.from_list_of_dicts(doc.get("identities", []))
            has_verified_mail = any(mail.get("verified") for mail in doc.get("mailAliases", []))
            # Cheap in-memory checks first, the queue lookup is a database query
            if not _needs_action(context, eppn, identities, limits, has_verified_mail):
                continue
            if context.cleaner_queue.user_in_queue(cleaner_type=CleanerType.IDENTITY_AGE, eppn=eppn):
                context.logger.debug(f"{eppn} already in queue")
                skipped_count += 1
                continue
            # The cleaner queue is the one thing a dry run writes, so the process job has something to work on
            context.cleaner_queue.save(
                CleanerQueueUser(eppn=eppn, cleaner_type=CleanerType.IDENTITY_AGE, identities=identities)
            )
        except Exception:
            # One bad user must not abort the sweep
            context.logger.exception(f"gather_identity_age_users: failed to queue user {eppn}")
            context.stats.count("identity_age_gather_failed")
            continue
        context.stats.count("identity_age_queued")
        queued_count += 1
    if not context.dry_run:
        pending_queued, pending_skipped = _gather_pending_unverifications(context)
        queued_count += pending_queued
        skipped_count += pending_skipped
    context.logger.info(
        f"gather_identity_age_users done: queued {queued_count}, skipped {skipped_count} already in queue"
    )


def _gather_pending_unverifications(context: Context) -> tuple[int, int]:
    """
    Queue users with an unverification that was requested but not recorded (see _reconcile_pending_unverifications).
    Such a user may no longer have a verified identity, so it is not found by the main sweep. Real runs only: a dry
    run never syncs and so never creates pending records.

    :returns: number of users queued and number skipped because they were already in the queue
    """
    queued_count = 0
    skipped_count = 0
    for pending in context.identity_age_db.iter_pending_unverifications():
        eppn = pending.eppn
        try:
            if context.cleaner_queue.user_in_queue(cleaner_type=CleanerType.IDENTITY_AGE, eppn=eppn):
                context.logger.debug(f"{eppn} already in queue")
                skipped_count += 1
                continue
            identities = context.central_db.get_user_by_eppn(eppn).identities
            context.cleaner_queue.save(
                CleanerQueueUser(eppn=eppn, cleaner_type=CleanerType.IDENTITY_AGE, identities=identities)
            )
        except UserDoesNotExist:
            continue
        except Exception:
            context.logger.exception(f"gather_identity_age_users: failed to queue user {eppn} with pending work")
            context.stats.count("identity_age_gather_failed")
            continue
        context.stats.count("identity_age_queued")
        queued_count += 1
    return queued_count, skipped_count


def process_identity_age_users(context: Context) -> None:
    """
    Take one user from the queue and warn about, or unverify, its identities that are close to or past the
    maximum verification age.

    A user without a verified mail address can not be warned. Such a user is left alone (and counted as
    identity_age_no_recipient_<type>) while the identity is in the warning window, but an identity that is
    past the maximum age is unverified immediately, without a warning record or notice period.

    The user is removed from the queue when taken. If processing fails the user is not retried until it is
    queued again by the next run of gather_identity_age_users.

    In dry run mode the user is taken from the queue and all decisions are made as in a real run, but against a
    separate notification collection (identity_age_notifications_dry_run, Context.identity_age_dry_run_db): the real
    collection is never read or written. A simulated warning or unverification is recorded there, so the full
    multi-day flow can be followed over several dry runs: a warning is recorded, and a dry run later than
    min_notice_days reports "would unverify" and records unverified_ts. As the central user stays verified in a dry
    run, an identity with a simulated unverification is skipped quietly by later dry runs (counted as
    identity_age_dry_run_already_simulated_<type>). Still no mail is queued, nothing is saved or synced and no
    identity is unverified. Each action that would have been taken is logged at info level ("Dry run: would ...")
    and counted as identity_age_dry_run_would_warn_<type> or identity_age_dry_run_would_unverify_<type> instead of
    the real counters. The check that an unverification landed in the central db is not simulated.

    Dropping the identity_age_notifications_dry_run collection gives a fresh dry run start.
    """
    queue_user = context.cleaner_queue.get_next_user(CleanerType.IDENTITY_AGE)
    if queue_user is None:
        context.logger.debug("Nothing to do")
        return
    eppn = queue_user.eppn
    context.stats.count("identity_age_users_checked")
    try:
        actions = _check_user(context, eppn, _limits(context))
        context.logger.info(f"process_identity_age_users: user {eppn} checked, {actions} actions")
    except (UserOutOfSync, AmTaskFailed) as e:
        context.logger.error(f"process_identity_age_users: failed to update user {eppn}: {e!r}")
        context.stats.count("identity_age_failed")
    except Exception:
        context.logger.exception(f"process_identity_age_users: unexpected error for user {eppn}")
        context.stats.count("identity_age_failed")


def _check_user(context: Context, eppn: str, limits: _Limits) -> int:
    """
    :returns: number of actions (warnings sent or identities unverified) taken
    """
    config = context.config.identity_age
    try:
        user = context.central_db.get_user_by_eppn(eppn)
    except UserDoesNotExist:
        return 0
    if user.terminated is not None:
        return 0

    actions = 0
    if not context.dry_run:
        actions += _reconcile_pending_unverifications(context, user, limits)
    to_warn: list[IdentityElement] = []
    to_unverify: list[IdentityElement] = []
    for identity in user.identities.verified:
        if not isinstance(identity, IdentityElement) or identity.identity_type not in config.identity_types:
            continue
        action = _classify_identity(context, eppn, user, identity, limits)
        if action == "warn":
            to_warn.append(identity)
        elif action == "unverify":
            to_unverify.append(identity)

    if to_warn:
        actions += _warn_user(context, user, to_warn, limits)
    if to_unverify:
        actions += _unverify_identities(context, user, to_unverify, limits)
    return actions


def _skip_already_unverified(
    context: Context,
    eppn: str,
    identity: IdentityElement,
    verified_at: datetime,
    notification: IdentityAgeNotification | None,
) -> bool:
    """
    :returns: True if the identity was already unverified for this verified_at (logged and counted here), in which
        case the caller must skip it
    """
    if notification is None or notification.unverified_ts is None:
        return False
    type_name = identity.identity_type.value
    if context.dry_run:
        # The central user stays verified in a dry run, this is the expected state after a simulated unverify
        context.logger.info(f"{eppn}: {type_name} identity unverification already simulated, skipping")
        context.stats.count(f"identity_age_dry_run_already_simulated_{type_name}")
        return True
    # Verified again with the very same verified_at after we unverified it. Don't unverify it again.
    context.logger.warning(
        f"{eppn}: {type_name} identity was already unverified for verified_at {verified_at} but is verified"
        " again without a new verification time, skipping"
    )
    context.stats.count(f"identity_age_unknown_{type_name}")
    return True


def _classify_identity(
    context: Context, eppn: str, user: User, identity: IdentityElement, limits: _Limits
) -> Literal["warn", "unverify"] | None:
    """
    Decide what to do about one verified identity of a configured type.

    :returns: "warn" if the user should be warned about the identity, "unverify" if the identity should be
        unverified, None if nothing is to be done with it now
    """
    status = get_identity_age_status(identity, limits.now, limits.max_age, limits.warning_period)
    type_name = identity.identity_type.value
    verified_at = identity.verified_at
    if status is IdentityAgeStatus.UNKNOWN or verified_at is None:
        context.logger.info(f"{eppn}: verification time of {type_name} identity is unknown")
        context.stats.count(f"identity_age_unknown_{type_name}")
        return None
    if status is IdentityAgeStatus.OK:
        return None

    notification = _notification_db(context).get(eppn, identity.identity_type, verified_at)
    if _skip_already_unverified(context, eppn, identity, verified_at, notification):
        return None
    warned_at = notification.warning_sent_ts if notification is not None else None
    if status is IdentityAgeStatus.EXPIRED and not user.mail_addresses.verified:
        # No warning can be delivered, so there is no notice to wait for: unverify right away
        return "unverify"
    if warned_at is None:
        # WARN, or EXPIRED but never warned (and the user has a mail address): warn now,
        # unverification is up to a later run
        return "warn"
    if status is IdentityAgeStatus.EXPIRED and warned_at + limits.min_notice <= limits.now:
        return "unverify"
    return None


def _notice_date(identity: IdentityElement, limits: _Limits) -> str:
    """
    The date the user will be told the identity expires. An identity that is already past its expiry
    will not be unverified until the user has had min_notice_days notice.
    """
    expires_at = identity_expires_at(identity, limits.max_age)
    notice_ends = limits.now + limits.min_notice
    if expires_at is None or expires_at < notice_ends:
        expires_at = notice_ends
    return expires_at.strftime("%Y-%m-%d")


def _verified_at_of(identity: IdentityElement) -> datetime:
    """verified_at of an identity that has been checked to have one"""
    if identity.verified_at is None:
        raise ValueError(f"{identity.identity_type.value} identity has no verified_at")
    return identity.verified_at


def _record_warnings_and_send(
    context: Context, user: User, identities: list[IdentityElement], send: Callable[[], int]
) -> bool:
    """
    Record a warning for every identity, then call send() (which queues ONE mail per verified address).

    The warnings are recorded BEFORE the mails are queued. If queueing fails for every address the records are
    removed so the warning is retried next run. If at least one mail was queued the records stay, so a
    failure can never cause the same mail to be queued on every run. (The only gap is a crash between
    recording and queueing, which loses a warning rather than repeating it.)

    :returns: True if at least one mail was queued
    """
    written: list[IdentityElement] = []
    db = _notification_db(context)

    def rollback() -> None:
        for written_identity in written:
            db.clear_warning(user.eppn, written_identity.identity_type, _verified_at_of(written_identity))

    try:
        for identity in identities:
            db.mark_warned(user.eppn, identity.identity_type, _verified_at_of(identity))
            written.append(identity)
        sent = send()
    except Exception:
        rollback()
        raise
    if sent == 0:
        rollback()
        return False
    return True


def _warn_user(context: Context, user: User, identities: list[IdentityElement], limits: _Limits) -> int:
    """
    Send ONE warning mail per verified address covering all the given identities close to expiry, and record a
    warning for each of them. The date in the mail is the earliest expiry among the identities.

    :returns: number of identities warned (0 if no mail was queued)
    """
    config = context.config.identity_age
    covered = [i for i in identities if i.verified_at is not None]
    if not covered:
        return 0
    names = ", ".join(i.identity_type.value for i in covered)

    if not user.mail_addresses.verified:
        # Nothing was delivered so nothing is recorded. The warning is retried on the next run, hopefully when
        # the user has a verified mail address. (An expired identity is unverified without a warning instead,
        # see _check_user.)
        for identity in covered:
            type_name = identity.identity_type.value
            context.logger.warning(f"User {user.eppn} has no verified mail address to warn about {type_name} identity")
            context.stats.count(f"identity_age_no_recipient_{type_name}")
        return 0

    expires_at = min(_notice_date(identity, limits) for identity in covered)
    if context.dry_run:
        context.logger.info(
            f"Dry run: would send expiry warning to {user.eppn} for identities [{names}] expiring {expires_at}"
            f" ({len(user.mail_addresses.verified)} verified addresses)"
        )
        # Record the simulated warning in the dry run collection. No mail is queued so there is nothing to roll back.
        _record_warnings_and_send(context, user, covered, lambda: 1)
        for identity in covered:
            context.stats.count(f"identity_age_dry_run_would_warn_{identity.identity_type.value}")
        return len(covered)

    sent = _record_warnings_and_send(
        context,
        user,
        covered,
        lambda: send_mail_to_user(
            context,
            user,
            lambda email, language, reference: EduidIdentityExpiryWarningEmail(
                email=email,
                reference=reference,
                language=language,
                site_name=context.config.eduid_site_name,
                expires_at=expires_at,
            ),
            expires_in=timedelta(days=config.mail_expires_in_days),
        ),
    )
    if not sent:
        context.logger.error(f"Failed to queue warning to user {user.eppn} about {names} identities")
        context.stats.count("identity_age_failed")
        return 0
    for identity in covered:
        context.stats.count(f"identity_age_warned_{identity.identity_type.value}")
    return len(covered)


def _unverified_payload_factory(context: Context) -> Callable[[str, str, str], EmailPayload]:
    def make_payload(email: str, language: str, reference: str) -> EmailPayload:
        return EduidIdentityUnverifiedEmail(
            email=email,
            reference=reference,
            language=language,
            site_name=context.config.eduid_site_name,
        )

    return make_payload


def _unverified_in_central(context: Context, eppn: str, identity_types: list[IdentityType]) -> set[IdentityType]:
    """
    Re-read the user from the central db and return the subset of identity_types that are not verified there.

    A successful sync only means the AM worker accepted the request, not that every change was applied.

    :raises: whatever the central db raises if the user can not be read
    """
    central = context.central_db.get_user_by_eppn(eppn)
    landed: set[IdentityType] = set()
    for identity_type in identity_types:
        current = central.identities.find(identity_type.value)
        if not isinstance(current, IdentityElement) or not current.is_verified:
            landed.add(identity_type)
    return landed


def _dry_run_unverify(
    context: Context,
    user: User,
    unverified: list[tuple[IdentityElement, datetime, datetime | None]],
    has_recipient: bool,
) -> int:
    """
    Dry run counterpart of the save/sync/record/notice part of _unverify_identities: log what would be done
    (one line for the unverification and one for the notice, if any), count it and record the simulated
    unverification in the dry run collection. Writes nothing else.

    :returns: number of identities that would be unverified
    """
    names = ", ".join(identity.identity_type.value for identity, _, _ in unverified)
    notices = ", ".join(
        f"{identity.identity_type.value}={warned_at.isoformat() if warned_at else 'none'}"
        for identity, _, warned_at in unverified
    )
    context.logger.info(
        f"Dry run: would unverify [{names}] for {user.eppn} (notice sent {notices}, no recipient={not has_recipient})"
    )
    for identity, _, _ in unverified:
        context.stats.count(f"identity_age_dry_run_would_unverify_{identity.identity_type.value}")
    for identity, verified_at, _ in unverified:
        _notification_db(context).mark_unverified(user.eppn, identity.identity_type, verified_at)
    if has_recipient and context.config.identity_age.send_unverified_notice:
        context.logger.info(
            f"Dry run: would send unverified notice to {user.eppn} for identities [{names}]"
            f" ({len(user.mail_addresses.verified)} verified addresses)"
        )
    return len(unverified)


def _unchanged_since_checked(user: User, identity: IdentityElement) -> bool:
    """
    :returns: True if the identity is still verified on the (reloaded) user with the same verified_at as when it
        was checked, False if it was changed (e.g. re-verified) since
    """
    current = user.identities.find(identity.key)
    return (
        isinstance(current, IdentityElement)
        and current.is_verified
        and identity.verified_at is not None
        and current.verified_at == identity.verified_at
    )


def _notice_period_passed(notification: IdentityAgeNotification | None, limits: _Limits) -> bool:
    """:returns: True if a warning is recorded that is at least min_notice old"""
    return (
        notification is not None
        and notification.warning_sent_ts is not None
        and notification.warning_sent_ts + limits.min_notice <= limits.now
    )


def _select_unverifiable(
    context: Context, user: User, identities: list[IdentityElement], limits: _Limits, has_recipient: bool
) -> list[tuple[IdentityElement, datetime, datetime | None]]:
    """
    Recheck each identity against the reloaded user and the notifications recorded now, and unverify (in memory
    only) those that are still eligible. A user without a verified mail address can not be warned, so no warning
    record or notice period is required for that user.

    :returns: (identity, verified_at, warning_sent_ts) for every identity that was unverified on the user
    """
    unverified: list[tuple[IdentityElement, datetime, datetime | None]] = []
    for identity in identities:
        verified_at = identity.verified_at
        # Skip identities that were changed (e.g. re-verified) since we looked at them
        if verified_at is None or not _unchanged_since_checked(user, identity):
            continue
        notification = _notification_db(context).get(user.eppn, identity.identity_type, verified_at)
        if notification is not None and notification.unverified_ts is not None:
            context.logger.info(f"{user.eppn}: {identity.identity_type.value} identity already unverified, skipping")
            continue
        if has_recipient and not _notice_period_passed(notification, limits):
            context.logger.info(
                f"{user.eppn}: not unverifying {identity.identity_type.value} identity, no sufficient notice recorded"
            )
            continue
        user.identities.unverify(identity.identity_type)
        unverified.append((identity, verified_at, notification.warning_sent_ts if notification is not None else None))
    return unverified


def _record_landed(
    context: Context,
    user: User,
    unverified: list[tuple[IdentityElement, datetime, datetime | None]],
    landed: set[IdentityType],
    has_recipient: bool,
) -> tuple[int, list[str]]:
    """
    Record the unverification (and count and log it) of every identity confirmed unverified in the central db.
    Identities still verified there are counted as sync mismatches and left unrecorded.

    :returns: number of identities recorded, and the type names to mention in the notice mail
    """
    done = 0
    landed_names: list[str] = []
    for identity, verified_at, _ in unverified:
        type_name = identity.identity_type.value
        if identity.identity_type not in landed:
            context.logger.warning(
                f"{user.eppn}: {type_name} identity still verified in the central db after sync, not recording"
                " unverification or sending notice"
            )
            context.stats.count("identity_age_sync_mismatch")
            context.stats.count(f"identity_age_sync_mismatch_{type_name}")
            # Known not to have landed, nothing is pending. The normal flow retries next cycle.
            _clear_pending(context, user.eppn, identity.identity_type, verified_at)
            continue
        done += 1
        try:
            _notification_db(context).mark_unverified(user.eppn, identity.identity_type, verified_at)
        except Exception:
            context.logger.exception(f"Failed to record unverification of {type_name} identity for {user.eppn}")
            context.stats.count("identity_age_failed")
        context.stats.count(f"identity_age_unverified_{type_name}")
        context.logger.info(f"Unverified {type_name} identity for user {user.eppn} (verified at {verified_at})")
        if has_recipient:
            landed_names.append(type_name)
        else:
            context.stats.count(f"identity_age_unverified_no_recipient_{type_name}")
            context.logger.warning(f"User {user.eppn} has no verified mail address, no notice about {type_name} sent")
    return done, landed_names


def _send_unverified_notice(context: Context, user: User, landed_names: list[str]) -> None:
    """
    Queue ONE unverified notice per verified address covering everything that landed. Failures are logged and
    counted as identity_age_failed, never raised.
    """
    try:
        queued = send_mail_to_user(
            context,
            user,
            _unverified_payload_factory(context),
            expires_in=timedelta(days=context.config.identity_age.mail_expires_in_days),
        )
        if queued == 0:
            context.logger.error(
                f"Failed to queue unverified notice for {', '.join(landed_names)} identities to {user.eppn}"
            )
            context.stats.count("identity_age_failed")
    except Exception:
        context.logger.exception(
            f"Failed to send unverified notice for {', '.join(landed_names)} identities to {user.eppn}"
        )
        context.stats.count("identity_age_failed")


def _clear_pending(context: Context, eppn: str, identity_type: IdentityType, verified_at: datetime) -> bool:
    """
    Remove the pending unverification marker. Failures are logged and counted, never raised.

    :returns: True if the marker was cleared
    """
    try:
        _notification_db(context).clear_unverify_requested(eppn, identity_type, verified_at)
    except Exception:
        context.logger.exception(f"Failed to clear pending unverification of {identity_type.value} for {eppn}")
        context.stats.count("identity_age_failed")
        return False
    return True


def _mark_requested(
    context: Context, user: User, unverified: list[tuple[IdentityElement, datetime, datetime | None]]
) -> bool:
    """
    Persist that the unverifications are about to be synced, so they can be reconciled if the job fails halfway.

    :returns: False if the markers could not be written, in which case nothing must be synced
    """
    try:
        for identity, verified_at, _ in unverified:
            context.identity_age_db.mark_unverify_requested(user.eppn, identity.identity_type, verified_at)
    except Exception:
        context.logger.exception(f"Failed to record pending unverification for {user.eppn}, not syncing")
        context.stats.count("identity_age_failed")
        return False
    return True


def _pending_outcome(user: User, pending: IdentityAgeNotification) -> Literal["landed", "not_landed", "reverified"]:
    """
    Compare a pending unverification with the freshly loaded central user. An identity that is not verified (or
    gone) means the unverification landed. A verified identity with the recorded verified_at means it did not, one
    with another verified_at was verified again since.
    """
    current = user.identities.find(pending.identity_type.value)
    if not isinstance(current, IdentityElement) or not current.is_verified:
        return "landed"
    normalise = IdentityAgeNotificationDB.normalise_verified_at
    if current.verified_at is not None and normalise(current.verified_at) == normalise(pending.verified_at):
        return "not_landed"
    return "reverified"


def _reconcile_one(context: Context, user: User, pending: IdentityAgeNotification) -> bool:
    """
    Resolve one pending unverification against the freshly loaded central user.

    :returns: True if the unverification had landed and was recorded now (a notice is due)
    """
    type_name = pending.identity_type.value
    outcome = _pending_outcome(user, pending)
    if outcome != "landed":
        context.logger.info(f"{user.eppn}: pending {type_name} unverification: {outcome}, clearing")
        _clear_pending(context, user.eppn, pending.identity_type, pending.verified_at)
        return False
    # This also clears the pending marker
    context.identity_age_db.mark_unverified(user.eppn, pending.identity_type, pending.verified_at)
    context.stats.count(f"identity_age_unverified_{type_name}")
    context.stats.count(f"identity_age_reconciled_{type_name}")
    context.logger.info(f"Reconciled {type_name} unverification for {user.eppn} (verified at {pending.verified_at})")
    return True


def _reconcile_pending_unverifications(context: Context, user: User, limits: _Limits) -> int:
    """
    Complete unverifications that were requested earlier but never recorded, e.g. because the job failed after the
    AM sync had applied the change. Looks only at the pending records, never at whether the identity is verified, as
    a landed unverification leaves nothing verified to find. Real runs only.

    One unverified notice (one mail per verified address) covers everything completed here.

    :returns: number of unverifications completed
    """
    completed: list[str] = []
    for pending in list(context.identity_age_db.iter_pending_unverifications(user.eppn)):
        try:
            if _reconcile_one(context, user, pending):
                completed.append(pending.identity_type.value)
        except Exception:
            context.logger.exception(f"Failed to reconcile pending unverification for {user.eppn}")
            context.stats.count("identity_age_failed")
    if not completed:
        return 0
    if not user.mail_addresses.verified:
        for type_name in completed:
            context.stats.count(f"identity_age_unverified_no_recipient_{type_name}")
        context.logger.warning(f"User {user.eppn} has no verified mail address, no notice about {completed} sent")
    elif context.config.identity_age.send_unverified_notice:
        _send_unverified_notice(context, user, completed)
    return len(completed)


def _unverify_identities(context: Context, user: User, identities: list[IdentityElement], limits: _Limits) -> int:
    """
    Unverify identities with a single save of the user.

    DEPLOY ORDER: the AM worker that has `identities` in the eduid_job_runner attribute allowlist
    (eduid/workers/am/ams/__init__.py) must be deployed BEFORE the gather/process_identity_age_users cron is
    enabled. After the sync the central db is re-read and only identities confirmed unverified there are recorded
    and mailed. With the wrong order nothing breaks but nothing is achieved either: the mismatch is counted
    (identity_age_sync_mismatch) and no record is left, so the identity is retried on every run.

    Requires a recorded warning at least min_notice old, except when the user has no verified mail address
    (no warning could be delivered). For such a user the unverification is recorded without a warning
    timestamp and no notice mail is sent.

    :returns: number of identities unverified
    """
    # Reload the user as it might have changed while the warnings were handled
    user = context.central_db.get_user_by_eppn(user.eppn)
    if user.terminated is not None:
        return 0

    original = user.model_copy(deep=True)
    has_recipient = bool(user.mail_addresses.verified)
    unverified = _select_unverifiable(context, user, identities, limits, has_recipient)
    if not unverified:
        return 0

    if context.dry_run:
        return _dry_run_unverify(context, user, unverified, has_recipient)

    # Persisted before the sync: if the sync lands but the job fails before recording it, the next run reconciles
    if not _mark_requested(context, user, unverified):
        return 0

    if not save_and_sync_user(context, user, original=original):
        context.logger.error(f"Failed to save and sync user {user.eppn} after unverifying identities")
        context.stats.count("identity_age_failed")
        return 0

    try:
        landed = _unverified_in_central(context, user.eppn, [identity.identity_type for identity, _, _ in unverified])
    except Exception:
        # Can't tell what landed: record nothing, the next run retries
        context.logger.exception(f"Failed to verify that identities were unverified centrally for {user.eppn}")
        context.stats.count("identity_age_failed")
        return 0

    done, landed_names = _record_landed(context, user, unverified, landed, has_recipient)
    if landed_names and context.config.identity_age.send_unverified_notice:
        _send_unverified_notice(context, user, landed_names)
    return done
