from .. import utils
from .. import session_pb2 as protobuf


class Post:
    """Class representing a post made in an open group"""

    _proto = None

    def __init__(self, raw=None, *, user=None, text=None):
        if isinstance(raw, bytes) or isinstance(raw, memoryview):
            msg = protobuf.Content()
            msg.ParseFromString(utils.remove_session_message_padding(raw))
            self._proto = msg.dataMessage
        if self._proto is None:
            # TODO: implement other kinds of construction methods for Posts
            raise ValueError('must provide raw message bytes')

    @property
    def text(self):
        """accessor for the post body"""
        return self._proto.body

    @property
    def username(self):
        """accessor for the username of the post's author"""
        if self.profile is None:
            return
        return self.profile.displayName

    @property
    def profile(self):
        """accessor for the user profile data containing things like username etc"""
        return self._proto.profile
