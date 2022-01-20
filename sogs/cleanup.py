import os
import time

from .web import app
from .db import query
from . import config, db

# Cleanup interval, in seconds.
INTERVAL = 10


def cleanup():
    with app.app_context():
        try:
            app.logger.debug("Pruning expired items")
            files = prune_files()
            msg_hist = prune_message_history()
            room_act = prune_room_activity()
            perm_upd = apply_permission_updates()
            exp_nonces = expire_nonce_history()
            app.logger.debug(
                f"Pruned {files} files, {msg_hist} msg hist, {room_act} room activity, "
                f"{exp_nonces} nonces; applied {perm_upd} perm updates."
            )
            return (files, msg_hist, room_act, perm_upd, exp_nonces)
        except Exception as e:
            app.logger.warning(f"Periodic database cleanup failed: {e}")
            return None


def prune_files():
    now = time.time()
    if db.have_returning:
        to_remove = [
            row[0] for row in query("DELETE FROM files WHERE expiry < :exp RETURNING path", exp=now)
        ]
    else:
        with db.transaction():
            to_remove = [
                row[0] for row in query("SELECT path FROM files WHERE expiry < :exp", exp=now)
            ]

            if not to_remove:
                return 0

            query("DELETE FROM files WHERE expiry < :exp", exp=now)

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
    count = query(
        "DELETE FROM message_history WHERE replaced < :t",
        t=time.time() - config.MESSAGE_HISTORY_PRUNE_THRESHOLD * 86400,
    ).rowcount

    if count > 0:
        app.logger.info("Pruned {} message edit/deletion records".format(count))
    return count


def prune_room_activity():
    count = query(
        "DELETE FROM room_users WHERE last_active < :t",
        t=time.time() - config.ROOM_ACTIVE_PRUNE_THRESHOLD * 86400,
    ).rowcount

    if count > 0:
        app.logger.info("Prune {} old room activity records".format(count))
    return count


def expire_nonce_history():
    return query("DELETE FROM user_request_nonces WHERE expiry < :exp", exp=time.time()).rowcount


def apply_permission_updates():
    with db.transaction():
        now = time.time()
        num_applied = query(
            """
            INSERT INTO user_permission_overrides (room, "user", read, write, upload, banned)
            SELECT room, "user", read, write, upload, banned FROM user_permission_futures
                WHERE at <= :now
            ON CONFLICT (room, "user") DO UPDATE SET
                read = COALESCE(excluded.read, user_permission_overrides.read),
                write = COALESCE(excluded.write, user_permission_overrides.write),
                upload = COALESCE(excluded.upload, user_permission_overrides.upload),
                banned = COALESCE(excluded.banned, user_permission_overrides.banned)
            """,
            now=now,
        ).rowcount
        if not num_applied:
            return 0

        query("DELETE FROM user_permission_futures WHERE at <= :now", now=now)

    if num_applied > 0:
        app.logger.info("Applied {} scheduled user permission updates".format(num_applied))
    return num_applied
