from ..db import query
from .. import config, utils
from .exc import NoSuchFile, NoSuchUser
import time


class File:
    """
    Class representing a user stored in the database.

    Properties:
        id - the numeric file id, i.e. primary key
        room - the Room that this file belongs to (only retrieved on demand).
        uploader - the User that uploaded this file (only retrieved on demand).
        size - the size (in bytes) of this file
        uploaded - unix timestamp when the file was uploaded
        expiry - unix timestamp when the file expires.  None for non-expiring files.
        path - the path of this file on disk, relative to the base data directory.
        filename - the suggested filename provided by the user.  None for there is no suggestion
            (this will always be the case for files uploaded by legacy Session clients).
    """

    def __init__(self, row=None, *, id=None):
        """
        Constructs a file from a pre-retrieved row *or* a file id.  Raises NoSuchFile if the id does
        not exist in the database.
        """
        if sum(x is not None for x in (id, row)) != 1:
            raise ValueError("File() error: exactly one of id/row is required")
        if id is not None:
            row = query("SELECT * FROM files WHERE id = :f", f=id).first()
            if not row:
                raise NoSuchFile(id)

        (
            self.id,
            self._fetch_room_id,
            self._fetch_uploader_id,
            self.size,
            self.uploaded,
            self.expiry,
            self.filename,
            self.path,
        ) = (
            row[c]
            for c in ('id', 'room', 'uploader', 'size', 'uploaded', 'expiry', 'filename', 'path')
        )
        self._uploader = None
        self._room = None

    @property
    def room(self):
        """
        Accesses the Room in which this image is posted; this is fetched from the database the first
        time this is accessed.  In theory this can return None if the Room is in the process of
        being deleted but the Room's uploaded files haven't been deleted yet.
        """
        if self._fetch_room_id is not None:
            from .room import Room

            try:
                self._room = Room(id=self._fetch_room_id)
            except NoSuchFile:
                pass
            self._fetch_room_id = None
        return self._room

    @property
    def room_id(self):
        """
        Accesses the id of the room to which this file was uploaded.  Equivalent to .room.id, except
        that we don't fetch/cache the Room row.
        """
        return self._fetch_room_id if self._room is None else self._fetch_room_id

    @property
    def uploader(self):
        """
        Accesses the User who uploaded this file.  Retrieves from the database the first time this
        is accessed.
        """

        if self._fetch_uploader_id is not None:
            from .user import User

            try:
                self._uploader = User(id=self._fetch_uploader_id)
            except NoSuchUser:
                pass
            self._fetch_uploader_id = None
        return self._uploader

    @property
    def uploader_id(self):
        """
        Accesses the id of the user who uploaded this file.  Equivalent to .uploader.id, except
        that we don't fetch/cache the User row.
        """
        return self._fetch_uploader_id if self._uploader is None else self._uploader.id

    def read(self):
        """Reads the file from disk, as bytes."""
        with open(self.path, 'rb') as f:
            return f.read()

    def read_base64(self):
        """Reads the file from disk and encodes as base64."""
        return utils.encode_base64(self.read())

    def set_expiry(self, duration=None, forever=False):
        """
        Updates the file expiry to `duration` seconds from now, or to unlimited if `forever` is
        True.  If duration is None (and not using forever) then the default expiry will be used.
        """
        expiry = (
            None
            if forever
            else time.time()
            + (duration if duration is not None else config.UPLOAD_DEFAULT_EXPIRY_DAYS)
        )
        query("UPDATE files SET expiry = :when WHERE id = :f", when=expiry, f=self.id)
        self.expiry = expiry
