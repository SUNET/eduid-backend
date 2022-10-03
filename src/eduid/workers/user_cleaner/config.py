from eduid.common.config.base import LoggingConfigMixin, RootConfig


class UserCleanerConfig(RootConfig, LoggingConfigMixin):
    mongo_uri: str = ""
