import os
import time

from .web import app, appdb, query
from . import config

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
            app.logger.debug(
                "Pruned {} files, {} msg hist, {} room activity, {} perm updates".format(
                    files, msg_hist, room_act, perm_upd
                )
            )
        except Exception as e:
            app.logger.warn(f"Periodic database cleanup failed: {e}")


def prune_files():
    with appdb.begin_nested():
        # Would love to use a single DELETE ... RETURNING here, but that requires sqlite 3.35+.
        now = time.time()
        to_remove = [row[0] for row in query("SELECT path FROM files WHERE expiry < :exp", exp=now)]

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
    with appdb.begin_nested():
        count = query(
            "DELETE FROM room_users WHERE last_active < :t",
            t=time.time() - config.ROOM_ACTIVE_PRUNE_THRESHOLD * 86400,
        ).rowcount

    if count > 0:
        app.logger.info("Prune {} old room activity records".format(count))
    return count


def apply_permission_updates():
    with appdb.begin_nested():
        now = time.time()
        num_applied = query(
            """
            INSERT INTO user_permission_overrides (room, user, read, write, upload, banned)
            SELECT room, user, read, write, upload, banned FROM user_permission_futures
                WHERE at <= :now
            ON CONFLICT (room, user) DO UPDATE SET
                read = COALESCE(excluded.read, read),
                write = COALESCE(excluded.write, write),
                upload = COALESCE(excluded.upload, upload),
                banned = COALESCE(excluded.banned, banned)
            """,
            now=now,
        ).rowcount
        if not num_applied:
            return 0

        query("DELETE FROM user_permission_futures WHERE at <= :now", now=now)

    if num_applied > 0:
        app.logger.info("Applied {} scheduled user permission updates".format(num_applied))
    return num_applied
