from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, MagicCookieMixin, MsgConfigMixin


class MobileProofingConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MsgConfigMixin):
    """
    Configuration for the lookup mobile proofing app
    """

    app_name = "lookup_mobile_proofing"
    lookup_mobile_broker_url: str = ""
