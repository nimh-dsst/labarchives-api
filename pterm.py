import os
from typing import Mapping, Any

import pytest
from dotenv import load_dotenv

import main as LA
from main import Index

type AnyDict = Mapping[str, AnyDict | str | bool | int | float]

load_dotenv()


api_url = os.getenv("API_URL", "https://api.labarchives.com")
akid = os.getenv("ACCESS_KEYID")
akpass = os.getenv("ACCESS_PWD")

if not akid or not akpass:
    pytest.fail("ACCESS_KEYID or ACCESS_PWD environment variables not set.")

client = LA.Client(base_url=api_url, akid=akid, akpass=akpass)

user = client.default_authenticate()

notebook = user.notebooks[Index.Name : "DSST Test Notebook"][0]

entries: LA.Entry[Any] = list(
    notebook[Index.Name : "API Deleted Items"][0][Index.Name : "Test Widgs"][
        0
    ].entries.values()
)

# print(entry.content)

# entry_content = json.loads(entry.content)

# entry_content["sketch"]["data"].append({
#     "type": "image",
#     "data": {},
#     "x": 10,
#     "y": 40,
#     "href": "https://placehold.co/600x400"
# })

# entry.content = json.dumps(entry_content)
