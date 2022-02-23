from ..web import app
from ..model.room import Room
from ..model.exc import NoSuchRoom

from .. import config

from werkzeug.routing import BaseConverter, ValidationError


class RoomTokenConverter(BaseConverter):
    regex = r"[\w-]{1,64}"

    def to_python(self, value):
        try:
            return Room(token=value)
        except NoSuchRoom:
            raise ValidationError()

    def to_value(self, value):
        return value.token


class AnySessionIDConverter(BaseConverter):
    """url converter that accepts any kind of session id"""

    regex = r"[01]5[0-9a-fA-F]{64}"

    def to_python(self, value):
        return value


class BlindSessionIDConverter(BaseConverter):
    """url converter that accepts only blind session ids"""

    regex = r"15[0-9a-fA-F]{64}"

    def to_python(self, value):
        return value


class UnblindedSessionIDConverter(BaseConverter):
    """url converter that accepts only unblinded session ids"""

    regex = r"05[0-9a-fA-F]{64}"

    def to_python(self, value):
        return value


app.url_map.converters['Room'] = RoomTokenConverter
app.url_map.converters['BlindSessionID'] = BlindSessionIDConverter

SessionIDConverter = AnySessionIDConverter

if config.REQUIRE_BLIND_KEYS:
    SessionIDConverter = BlindSessionIDConverter

app.url_map.converters['SessionID'] = SessionIDConverter
