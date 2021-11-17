import logging
import os
import time

from .timer import timer
from .web import app
from . import db
from . import config


@timer(10)
def test_timer(signal):
    with app.app_context():
        app.logger.debug("Pruning expired items")
        files = prune_files()
        msg_hist = prune_message_history()
        room_act = prune_room_activity()
        perm_upd = apply_permission_updates()
        app.logger.debug(
            "Pruned {} files, {} msg hist, {} room activity, {} perm updates".format(
                files, msg_hist, room_act, perm_upd
            )
        )


def prune_files():
    with db.conn as conn:
        # Would love to use a single DELETE ... RETURNING here, but that requires sqlite 3.35+.
        now = time.time()
        cur = conn.cursor()
        cur.execute("SELECT path FROM files WHERE expiry < ?", (now,))
        to_remove = [row[0] for row in cur]

        if not to_remove:
            return 0

        conn.execute("DELETE FROM files WHERE expiry <= ?", (now,))

    # Committed the transaction, so the files are gone: now go ahead and remove them from disk.
    unlink_count = 0
    for path in to_remove:
        try:
            os.unlink(path)
            unlink_count += 1
        except FileNotFoundError:
            pass
        except Exception as e:
            app.logger.error("Unable to remove expired upload '{}' from disk: {}".format(path, e))

    app.logger.info(
        "Pruned {} expired/deleted files{}".format(
            len(to_remove),
            " ({} unlinked)".format(unlink_count) if unlink_count != len(to_remove) else "",
        )
    )
    return len(to_remove)


def prune_message_history():
    with db.conn as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM message_history WHERE replaced < ?",
            (time.time() - config.MESSAGE_HISTORY_PRUNE_THRESHOLD * 86400,),
        )
        count = cur.rowcount

    if count > 0:
        app.logger.info("Pruned {} message edit/deletion records".format(count))
    return count


def prune_room_activity():
    with db.conn as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM room_users WHERE last_active < ?",
            (time.time() - config.ROOM_ACTIVE_PRUNE_THRESHOLD * 86400,),
        )
        count = cur.rowcount

    if count > 0:
        app.logger.info("Prune {} old room activity records".format(count))
    return count


def apply_permission_updates():
    with db.conn as conn:
        now = time.time()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_permission_overrides (room, user, read, write, upload)
            SELECT room, user, read, write, upload FROM user_permission_futures WHERE at <= ?
            ON CONFLICT DO UPDATE SET
                read = COALESCE(excluded.read, read),
                write = COALESCE(excluded.write, write),
                upload = COALESCE(excluded.upload, upload)
            """,
            (now,),
        )
        num_applied = cur.rowcount
        if not num_applied:
            return 0

        cur.execute("DELETE FROM user_permission_futures WHERE at <= ?", (now,))

    logging.info("Applied {} scheduled user permission updates".format(num_applied))
    return num_applied
