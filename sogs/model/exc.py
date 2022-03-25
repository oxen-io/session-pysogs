from ..web import app
from .. import http
import flask


class NotFound(LookupError):
    """Base class for NoSuchRoom, NoSuchFile, etc."""

    pass


class NoSuchRoom(NotFound):
    """Thrown when trying to construct a Room from a token that doesn't exist"""

    def __init__(self, token):
        self.token = token
        super().__init__(f"No such room: {token}")


class NoSuchFile(NotFound):
    """Thrown when trying to construct a File from an id that doesn't exist"""

    def __init__(self, id):
        self.id = id
        super().__init__(f"No such file: {id}")


class NoSuchUser(NotFound):
    """Thrown when attempting to retrieve a user that doesn't exist and auto-vivification of the
    user room is disabled"""

    def __init__(self, session_id):
        self.session_id = session_id
        super().__init__(f"No such user: {session_id}")


class NoSuchPost(NotFound):
    """Thrown when attempting to retrieve or reference a post that doesn't exist"""

    def __init__(self, id):
        self.id = id
        super().__init__(f"No such post: {id}")


class AlreadyExists(RuntimeError):
    """
    Thrown when attempting to create a record (e.g. a Room) that already exists.

    e.type is the type object (e.g. sogs.model.Room) that could not be constructed, if applicable.
    e.value is the unique value that already exists (e.g. the room token), if applicable.
    """

    def __init__(self, msg, type=None, value=None):
        super().__init__(msg)
        self.type = type
        self.value = value


class BadPermission(RuntimeError):
    """Thrown when attempt to perform an action that the given user does not have permission to do;
    for example, attempting to delete someone else's posts when not a moderator."""

    def __init__(self, msg=None):
        super().__init__("Permission denied" if msg is None else msg)


class InvalidData(RuntimeError):
    """Thrown if something in model was fed invalid data, for example a signature of an invalid
    size, or an unparseable entity."""


class PostRejected(RuntimeError):
    """
    Thrown when a post is refused for some reason other than a permission error (e.g. the post
    contains bad words)
    """

    def __init__(self, msg=None):
        super().__init__("Post rejected" if msg is None else msg)


class PostRateLimited(PostRejected):
    """Thrown when attempting to post too frequently in a room"""

    def __init__(self, msg=None):
        super().__init__("Rate limited" if msg is None else msg)


# Map uncaught model exceptions into flask http exceptions
@app.errorhandler(NotFound)
def abort_bad_room(e):
    flask.abort(http.NOT_FOUND)


@app.errorhandler(BadPermission)
def abort_perm_denied(e):
    flask.abort(http.FORBIDDEN)


@app.errorhandler(PostRejected)
def abort_post_rejected(e):
    flask.abort(http.TOO_MANY_REQUESTS)


@app.errorhandler(InvalidData)
def abort_invalid_data(e):
    flask.abort(http.BAD_REQUEST)
