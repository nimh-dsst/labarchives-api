import os
from typing import Union

from dotenv import load_dotenv


class Config:
    def __init__(
        self,
        api_url: Union[str, None],
        access_key_id: Union[str, None],
        access_password: Union[str, None],
        ssl_cer: Union[str, None],
        app_host: Union[str, None],
    ):
        load_dotenv()
        self.api_url: Union[str, None] = os.getenv("api_url")
        self.access_key_id: Union[str, None] = os.getenv("access_key_id")
        self.access_password: Union[str, None] = os.getenv("access_password")
        self.ssl_cer: Union[str, None] = os.getenv("ssl_cer")
        self.app_host: Union[str, None] = os.getenv("app_host")


config: Config = Config(
    api_url=None,
    access_key_id=None,
    access_password=None,
    ssl_cer=None,
    app_host=None,
)
