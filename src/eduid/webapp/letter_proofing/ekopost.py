import base64
import json
from datetime import datetime
from io import BytesIO

from hammock import Hammock

from eduid.webapp.letter_proofing.settings.common import LetterProofingConfig

__author__ = "john"


class EkopostException(Exception):
    pass


class Ekopost:
    def __init__(self, config: LetterProofingConfig):
        self.config = config

        auth = None
        if config.ekopost_api_user and config.ekopost_api_pw:
            auth = (config.ekopost_api_user, config.ekopost_api_pw)

        self.ekopost_api = Hammock(config.ekopost_api_uri, auth=auth, verify=config.ekopost_api_verify_ssl)

    def send(self, eppn: str, document: BytesIO):
        """
        Send a letter containing a PDF-document
        to the recipient specified in the document.

        :param eppn: eduPersonPrincipalName
        :param document: PDF-document to be sent
        """

        # Output date is set it to current time since
        # we want to send the letter as soon as possible.
        output_date = str(datetime.utcnow())

        # An easily identifiable name for the campaign and envelope
        letter_id = eppn + "+" + output_date

        # Create a campaign and the envelope that it should contain
        campaign = self._create_campaign(letter_id, output_date, "eduID")
        color = "false"
        if self.config.ekopost_api_color:
            color = "true"
        envelope = self._create_envelope(
            campaign_id=campaign["id"],
            name=letter_id,
            color=color,
            postage=self.config.ekopost_api_postage,
            plex=self.config.ekopost_api_plex,
        )

        # Include the PDF-document to send
        self._create_content(campaign["id"], envelope["id"], document.getvalue())

        # To mark the letter as ready to be printed and sent:
        # 1. Close the envelope belonging to the campaign.
        # 2. Close the campaign that holds the envelope.
        self._close_envelope(campaign["id"], envelope["id"])
        closed_campaign = self._close_campaign(campaign["id"])

        return closed_campaign["id"]

    def _create_campaign(self, name: str, output_date: str, cost_center: str):
        """
        Create a new campaign

        :param name: A name to identify the campaign.
        :param output_date: Date in UTC when the envelope
                            should be printed and distributed.
        :param cost_center: The internal cost center.
        """
        campaign_data = json.dumps({"name": name, "output_date": output_date, "cost_center": cost_center})

        response = self.ekopost_api.campaigns.POST(data=campaign_data, headers={"Content-Type": "application/json"})

        if response.status_code == 200:
            return response.json()

        raise EkopostException(f"Ekopost exception: {response.status_code!s} {response.text!s}")

    def _create_envelope(
        self, campaign_id: str, name: str, postage: str = "priority", plex: str = "simplex", color: str = "false"
    ):
        """
        Create an envelope for a specified campaign

        :param campaign_id: Id of the campaign within which to create the envelope
        :param name: A name to identify the envelope
        :param postage: Send with 'priority' to deliver within one working
                        day after printing, or send with 'economy' to deliver
                        within four working days after printing.
        :param plex: Use 'simplex' to print on one page or 'duplex' to print
                     on both front and back.
        :param color: Print in color (CMYK) or set to false for black and white.
        """
        envelope_data = json.dumps({"name": name, "postage": postage, "plex": plex, "color": color})

        response = self.ekopost_api.campaigns(campaign_id).envelopes.POST(
            data=envelope_data, headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            return response.json()

        raise EkopostException(f"Ekopost exception: {response.status_code!s} {response.text!s}")

    def _create_content(
        self,
        campaign_id: str,
        envelope_id: str,
        data: bytes,
        mime: str = "application/pdf",
        content_type: str = "document",
    ):
        """
        Create the content that should be linked to an envelope

        :param campaign_id: Unique id of a campaign within which the envelope exists
        :param envelope_id: Unique id of an envelope to add the content to
        :param data: The PDF document
        :param mime: The document's mime type
        :param content_type: Content type, which can be either 'document' or 'attachment'
        """
        content_data = json.dumps(
            {
                "campaign_id": campaign_id,
                "envelope_id": envelope_id,
                "data": base64.b64encode(data).decode("utf-8"),  # Needs to be unicode for json
                "mime": mime,
                "length": len(data),
                "type": content_type,
            }
        )

        response = (
            self.ekopost_api.campaigns(campaign_id)
            .envelopes(envelope_id)
            .content.POST(data=content_data, headers={"Content-Type": "application/json"})
        )

        if response.status_code == 200:
            return response.json()

        raise EkopostException(f"Ekopost exception: {response.status_code!s} {response.text!s}")

    def _close_envelope(self, campaign_id: str, envelope_id: str):
        """
        Change an envelope state to closed and mark it as ready for print & distribution.
        :param campaign_id: Unique id of a campaign within which the envelope exists
        :param envelope_id: Unique id of the envelope that should be closed
        """
        response = (
            self.ekopost_api.campaigns(campaign_id)
            .envelopes(envelope_id)
            .close.POST(headers={"Content-Type": "application/json"})
        )

        if response.status_code == 200:
            return response.json()

        raise EkopostException(f"Ekopost exception: {response.status_code!s} {response.text!s}")

    def _close_campaign(self, campaign_id: str):
        """
        Change a campains state to closed and mark it and all its
        envelopes as ready for print & distribution.

        :param campaign_id: Unique id of a campaign that should be closed
        """
        response = self.ekopost_api.campaigns(campaign_id).close.POST(headers={"Content-Type": "application/json"})

        if response.status_code == 200:
            return response.json()

        raise EkopostException(f"Ekopost exception: {response.status_code!s} {response.text!s}")
