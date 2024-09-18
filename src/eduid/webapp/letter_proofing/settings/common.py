from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, MagicCookieMixin, MsgConfigMixin


class LetterProofingConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MsgConfigMixin):
    """
    Configuration for the letter proofing app
    """

    app_name: str = "letter_proofing"

    letter_wait_time_hours: int = 336  # 2 weeks

    ekopost_api_uri: str = "https://api.ekopost.se"
    ekopost_api_verify_ssl: bool = True
    ekopost_api_user: str = ""
    ekopost_api_pw: str = ""
    # Print in color (CMYK) or set to false for black and white.
    ekopost_api_color: bool = False
    # Send with 'priority' to deliver within one working day after printing, or send with 'economy' to deliver
    # within four working days after printing.
    ekopost_api_postage: str = "priority"
    # Use 'simplex' to print on one page or 'duplex' to print on both front and back.
    ekopost_api_plex: str = "simplex"
    # Setting ekopost_debug_pdf to a path means that the other ekopost settings will be ignored and that the pdf
    # only will be written to to the supplied path, not sent to the letter service.
    ekopost_debug_pdf_path: str | None = None

    # Remove expired states on GET /proofing if this is set to True
    backwards_compat_remove_expired_state: bool = False
