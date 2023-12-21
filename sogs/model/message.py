from .. import config
from ..db import insert_and_get_row, query

from .user import User

import time


class Message:
    """Class representing a DM between users

    Properties:
        sender: sender user of the message
        recip: recipant user of the message
        data: opaque message data
        signature: signature of data
        alt_id: signing key if not 25-blinded session id
    """

    def __init__(self, row=None, *, sender=None, recip=None, data=None, alt_id=None):
        """
        Constructs a Message from a pre-retrieved row *or* sender recipient and data.
        """
        if row is None:
            if None in (sender, recip, data):
                raise ValueError("Message() error: no row or data provided")
            if not all(isinstance(arg, User) for arg in (sender, recip)):
                raise ValueError("Message() error: sender or recipient was not a User model")

            row = insert_and_get_row(
                """
                INSERT INTO inbox (sender, recipient, body, expiry, alt_id)
                VALUES (:sender, :recipient, :data, :expiry, :alt_id)
                """,
                "inbox",
                "id",
                sender=sender.id,
                recipient=recip.id,
                data=data,
                expiry=time.time() + config.DM_EXPIRY,
                alt_id=alt_id,
            )
        # sanity check
        assert row is not None
        self._row = row

    @staticmethod
    def delete_all(*, recip=None, sender=None):
        """Delete all messages sent to a user or from a user.
        returns the number of rows affected.
        """
        if sum(bool(x) for x in (sender, recip)) != 1:
            raise ValueError("delete_all(): exactly one of sender or recipient is required")

        result = query(
            f"DELETE FROM inbox WHERE {'recipient' if recip else 'sender'} = :id",
            id=recip.id if recip else sender.id,
        )
        return result.rowcount

    @staticmethod
    def to(user, since=None, limit=None):
        """get all message for a user, returns a generator"""
        rows = query(
            f"""
            SELECT * FROM inbox WHERE recipient = :recip
            {'AND id > :since_id' if since else ''}
            ORDER BY id
            {'LIMIT :limit' if limit else ''}
            """,
            recip=user.id,
            since_id=since,
            limit=limit,
        )
        for row in rows:
            yield Message(row=row)

    @staticmethod
    def sent(user, since=None, limit=None):
        """get all messages we sent, returns a generator"""
        rows = query(
            f"""
            SELECT * FROM inbox WHERE sender = :sender
            {'AND id > :since_id' if since else ''}
            ORDER BY id
            {'LIMIT :limit' if limit else ''}
            """,
            sender=user.id,
            since_id=since,
            limit=limit,
        )
        for row in rows:
            yield Message(row=row)

    @property
    def id(self):
        return self._row["id"]

    @property
    def posted_at(self):
        return self._row["posted_at"]

    @property
    def expires_at(self):
        return self._row["expiry"]

    @property
    def data(self):
        return self._row['body']

    @property
    def sender(self):
        if not hasattr(self, "_sender"):
            self._sender = User(id=self._row['sender'], autovivify=False)
        return self._sender

    @property
    def signing_key(self):
        if not hasattr(self, "_signing_key"):
            self._signing_key = self._row['alt_id']
            if self._signing_key is None:
                self._signing_key = User(id=self._row['sender'], autovivify=False).session_id
        return self._signing_key

    @property
    def recipient(self):
        if not hasattr(self, "_recip"):
            self._recip = User(id=self._row['recipient'], autovivify=False)
        return self._recip
