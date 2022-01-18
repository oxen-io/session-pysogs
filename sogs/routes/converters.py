from ..web import app
from ..model.room import Room
from ..model.exc import NoSuchRoom

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


class SessionIDConverter(BaseConverter):
    regex = r"05[0-9a-fA-F]{64}"

    def to_python(self, value):
        return value


app.url_map.converters['Room'] = RoomTokenConverter
app.url_map.converters['SessionID'] = SessionIDConverter
