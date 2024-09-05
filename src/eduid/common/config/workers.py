from pydantic import Field

from eduid.common.config.base import WorkerConfig


class AmConfig(WorkerConfig):
    """
    Configuration for the attribute manager celery worker
    """

    new_user_date: str = "2001-01-01"
    action_plugins: list = Field(default_factory=lambda: ["tou"])


class MsgConfig(WorkerConfig):
    """
    Configuration for the msg celery worker
    """

    audit: bool = True
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


class MobConfig(WorkerConfig):
    """
    Configuration for the lookup mobile celery worker
    """

    log_path: str = ""
    teleadress_client_password: str = ""
    teleadress_client_user: str = ""
    teleadress_client_url: str = "http://api.teleadress.se/WSDL/nnapiwebservice.wsdl"
    teleadress_client_port: str = "NNAPIWebServiceSoap"
