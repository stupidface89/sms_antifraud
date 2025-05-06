import json
import requests

from scenario.tools import cyrillic_translate
from settings import URL_GET_RANDOM_NAME
from api_master.exceptions import CouldNotGetName
from dataclasses import dataclass, field


@dataclass
class Name:
    first_name: str
    first_name_translate: str
    last_name: str
    last_name_translate: str


def get_name():
    try:
        response = requests.get(URL_GET_RANDOM_NAME).text
        first_name = json.loads(response).get('first_name')
        last_name = json.loads(response).get('last_name')
    except Exception as e:
        raise CouldNotGetName from e

    return Name(first_name=first_name,
                first_name_translate=cyrillic_translate(first_name),
                last_name=last_name,
                last_name_translate=cyrillic_translate(last_name))
