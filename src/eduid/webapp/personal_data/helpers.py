from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class PDataMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # successfully saved personal data
    save_success = "pd.save-success"
    # validation error: missing required field
    required = "pdata.field_required"
    # validation error: illegal characters
    special_chars = "only allow letters"
