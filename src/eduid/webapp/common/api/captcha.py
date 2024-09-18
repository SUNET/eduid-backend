from base64 import b64encode
from io import BytesIO

from captcha.audio import AudioCaptcha
from captcha.image import ImageCaptcha

from eduid.common.config.base import CaptchaConfigMixin
from eduid.common.config.exceptions import BadConfiguration

__author__ = "lundberg"


class InternalCaptcha:
    def __init__(self, config: CaptchaConfigMixin):
        self.image_generator = ImageCaptcha(
            height=config.captcha_height,
            width=config.captcha_width,
            fonts=[str(path) for path in config.captcha_fonts],
            font_sizes=config.captcha_font_size,
        )
        self.audio_generator = AudioCaptcha()

    def get_request_payload(self, answer: str) -> dict[str, str]:
        with BytesIO() as f:
            image_data = self.image_generator.generate_image(chars=answer)
            image_data.save(fp=f, format="PNG", optimize=True)
            b64_img = b64encode(f.getvalue()).decode("ascii")

        audio_data: bytearray = self.audio_generator.generate(chars=answer)
        b64_audio = b64encode(audio_data).decode("ascii")

        return {
            "captcha_img": f"data:image/png;base64,{b64_img}",
            "captcha_audio": f"data:audio/wav;base64,{b64_audio}",
        }


def init_captcha(config: CaptchaConfigMixin) -> InternalCaptcha:
    """
    Add captcha to the app.
    """
    if not isinstance(config, CaptchaConfigMixin):
        raise BadConfiguration("CaptchaConfigMixin is not implemented by the config class")
    return InternalCaptcha(config=config)
