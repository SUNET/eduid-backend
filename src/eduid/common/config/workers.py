from eduid.common.config.base import WorkerConfig


class AmConfig(WorkerConfig):
    """
    Configuration for the attribute manager celery worker
    """

    new_user_date: str = "2001-01-01"


class MsgConfig(WorkerConfig):
    """
    Configuration for the msg celery worker
    """

    devel_mode: bool = False
    mail_host: str = "localhost"
    mail_password: str = ""
    mail_port: int = 25
    mail_starttls: bool = False
    mail_username: str = ""
    mongo_dbname: str = "eduid_msg"
    navet_api_pw: str = ""
    navet_api_uri: str = ""
    navet_api_user: str = ""
    navet_api_verify_ssl: bool = False
    sms_acc: str = ""
    sms_key: str = ""
    sms_sender: str = "eduID"
    template_dir: str = ""
