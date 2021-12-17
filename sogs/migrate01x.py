# Migration code for upgrading from a 0.1.x SOGS database.  The database structure is completely
# changed, and so this is technically more like an import than a migration.

from . import config
from . import db
from . import utils
import os
import logging
import time
import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.install(milliseconds=True, isatty=True, logger=logger, level=config.LOG_LEVEL)


def migrate01x(conn):

    # Do the entire import in one transaction so that if anything fails we leave the db empty (so
    # that retrying will import from scratch).
    with conn:

        # Old database database.db is a single table database containing just the list of rooms:
        #    CREATE TABLE IF NOT EXISTS main (
        #        id TEXT PRIMARY KEY, -- now called token
        #        name TEXT,
        #        image_id TEXT -- entirely unused.
        #    )

        with db.sqlite_connect("database.db") as main_db:
            rooms = [(r[0], r[1]) for r in main_db.execute("SELECT id, name FROM main")]

        logger.warn("{} rooms to import".format(len(rooms)))

        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS room_import_hacks (
                room INTEGER PRIMARY KEY NOT NULL REFERENCES rooms(id),
                old_message_id_max INTEGER NOT NULL,
                message_id_offset INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS file_id_hacks (
                room INTEGER NOT NULL REFERENCES rooms(id),
                old_file_id INTEGER NOT NULL,
                file INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                PRIMARY KEY(room, old_file_id)
            )
            """
        )

        used_room_hacks, used_file_hacks = False, False

        ins_user = """
            INSERT INTO users (session_id, last_active) VALUES (?, 0.0)
            ON CONFLICT (session_id) DO NOTHING
            """

        total_rooms, total_msgs, total_files = 0, 0, 0

        for room_token, room_name in rooms:
            room_db_path = "rooms/{}.db".format(room_token)
            if not os.path.exists(room_db_path):
                logger.warn(
                    "Skipping room {}: database {} does not exist".format(room_token, room_db_path)
                )
                continue

            logger.info("Importing room {} -- {}...".format(room_token, room_name))

            cur.execute("INSERT INTO rooms (token, name) VALUES (?, ?)", (room_token, room_name))
            room_id = cur.lastrowid

            with db.sqlite_connect(room_db_path) as rconn:

                # Messages were stored in this:
                #
                #    CREATE TABLE IF NOT EXISTS messages (
                #        id INTEGER PRIMARY KEY,
                #        public_key TEXT,
                #        timestamp INTEGER,
                #        data TEXT,
                #        signature TEXT,
                #        is_deleted INTEGER
                #    );
                #
                # where public_key is the session_id (in hex), timestamp is in milliseconds since
                # unix epoch, data and signature are in base64 (wtf), data is typically padded from
                # the client (i.e. to the next multiple, with lots of 0s on the end).  If the
                # message was deleted then it remains here but `is_deleted` is set to 1 (data and
                # signature should be NULL as well, but older versions apparently didn't do that and
                # migrations never fixed it), plus we have a row in here:
                #
                #    CREATE TABLE IF NOT EXISTS deleted_messages (
                #        id INTEGER PRIMARY KEY,
                #        deleted_message_id INTEGER
                #    );
                #
                # where the `id` of this table is returned to the Session client so that they can
                # query for "deletions since [id]".
                #
                # This introduces some major complications, though: Session message polling works by
                # requesting messages (and deletions) since a given id, but we can't preserve IDs
                # because there are guaranteed to be duplicates across rooms.  So we use this
                # room_import_hacks defined above to figure this out:
                #
                #    - if requesting messages in a room since some id  <= old_message_id_max then we
                #      actually query messages in the room since id + message_id_offset.
                #
                # Deletions doesn't have the same complication because in the new database they use
                # a monotonic updates field that we can make conform (for imported rows) to the
                # imported deletion ids.

                id_offset = cur.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM messages").fetchone()[
                    0
                ]
                top_old_id, updated, imported_msgs = -1, 0, 0

                n_msgs = rconn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

                last_id, dupe_dels = -1, 0

                for id, session_id, timestamp, data, signature, deleted in rconn.execute(
                    """
                    SELECT messages.id, public_key AS session_id, timestamp, data, signature,
                        CASE WHEN is_deleted THEN deleted_messages.id ELSE NULL END AS deleted
                    FROM messages LEFT JOIN deleted_messages
                        ON messages.id = deleted_messages.deleted_message_id
                    ORDER BY messages.id
                    """
                ):
                    if top_old_id == -1:
                        id_offset -= id
                    if id > top_old_id:
                        top_old_id = id
                    if id == last_id:
                        # There are duplicates in the deleted_messages table (WTF) that can give us
                        # multiple rows through the join, so skip duplicates if they occur.
                        dupe_dels += 1
                        continue
                    else:
                        last_id = id

                    # NB: the old database cleared the session ID when deleting a message (which is
                    # bad, because no auditability at all), but also cleared it by setting it to the
                    # fixed string 'deleted' because I guess the author didn't know NULL was a
                    # thing?  We import them as such because our session_ids *can't* be null (and we
                    # no longer clear it when deleting), but the data is gone from the imported
                    # table so there's not much else we can do.

                    cur.execute(ins_user, (session_id,))

                    if config.IMPORT_ADJUST_MS:
                        timestamp += config.IMPORT_ADJUST_MS

                    # Timestamp is in unix epoch *milliseconds* for some non-standard reason.
                    timestamp /= 1000.0

                    if data is not None and signature is not None and deleted is None:
                        # Regular message

                        # Data was pointlessly store padded *and* base64 encoded, so decode and
                        # unpad it:
                        data = utils.decode_base64(data)
                        data_size = len(data)
                        data = utils.remove_session_message_padding(data)

                        # Signature was just base64 encoded:
                        signature = utils.decode_base64(signature)
                        if len(signature) != 64:
                            raise RuntimeError(
                                "Unexpected data: {} message id={} has invalid signature".format(
                                    room_db_path, id
                                )
                            )

                        cur.execute(
                            """
                            INSERT INTO messages
                                (id, room, user, posted, data, data_size, signature)
                            VALUES (?, ?, (SELECT id FROM users WHERE session_id = ?), ?, ?, ?, ?)
                            """,
                            (
                                id + id_offset,
                                room_id,
                                session_id,
                                timestamp,
                                data,
                                data_size,
                                signature,
                            ),
                        )

                    elif (
                        deleted is not None
                        # Deleted messages are usually set to the fixed string "deleted" (why not
                        # NULL?) for data and signature, so accept either null or that string if the
                        # other columns indicate a deleted message.
                        and data in (None, "deleted")
                        and signature in (None, "deleted")
                    ):

                        # Deleted message; we still need to insert a tombstone for it, and copy the
                        # deletion id as the "updated" field.  (We do this with a second query
                        # because the first query is going to trigger an automatic update of the
                        # field).

                        updated += 1
                        cur.execute(
                            """
                            INSERT INTO messages (id, room, user, posted)
                            VALUES (?, ?, (SELECT id FROM users WHERE session_id = ?), ?)
                            """,
                            (id + id_offset, room_id, session_id, timestamp),
                        )

                    else:
                        raise RuntimeError(
                            "Inconsistent message in {} database: message id={} has inconsistent "
                            "deletion state (data: {}, signature: {}, del row: {})".format(
                                room_db_path,
                                id,
                                data is not None,
                                signature is not None,
                                deleted is not None,
                            )
                        )

                    cur.execute(
                        "UPDATE messages SET updated = ? WHERE id = ?", (updated, id + id_offset)
                    )
                    imported_msgs += 1
                    if imported_msgs % 5000 == 0:
                        logger.info("- ... imported {}/{} messages".format(imported_msgs, n_msgs))

                logger.info(
                    "- migrated {} messages, {} duplicate deletions ignored".format(
                        imported_msgs, dupe_dels
                    )
                )

                # Old SOGS has a bug where it inserts duplicate deletion tombstones (see above), but
                # this means that our updated count might not be large enough for existing Session
                # clients to not break: they will be fetching deletion ids > X, but if we have 100
                # duplicates, the room's update counter would be X-100 and so existing clients
                # wouldn't actually fetch any new deletions until the counter catches up.  Fix that
                # up by incrementing the updates counter if necessary.
                top_del_id = rconn.execute("SELECT MAX(id) FROM deleted_messages").fetchone()[0]
                if top_del_id is None:
                    top_del_id = 0

                cur.execute(
                    "UPDATE rooms SET updates = ? WHERE id = ?", (max(updated, top_del_id), room_id)
                )

                # If we have to offset rowids then make sure the hack table exists and insert our
                # hack.
                if id_offset != 0:
                    used_room_hacks = True
                    cur.execute(
                        """
                        INSERT INTO room_import_hacks (room, old_message_id_max, message_id_offset)
                        VALUES (?, ?, ?)
                        """,
                        (room_id, top_old_id, id_offset),
                    )

                # Files were stored in:
                #
                #    CREATE TABLE files (
                #        id TEXT PRIMARY KEY,
                #        timestamp INTEGER
                #    );
                #
                # where `id` is a randomized integer value, but stored in a TEXT because yeah.  (The
                # randomization was completely pointless: it was there for the file server mode,
                # which we don't care about).  `timestamp` is milliseconds rather than seconds
                # because yeah.
                #
                # The actual file on disk is stored in ./files/{ROOM}_files/{id}.  We leave it there
                # (rather than moving it to the new location) as it isn't a big deal to let it rest
                # there until expiry.
                #
                # Since we have to preserve the old random IDs for existing Session clients (until
                # they expire), we need to track old_id -> new_id, and we do that using the
                # file_id_hacks table that we created above.  If this table exists then attempting
                # to download a file with an id that doesn't exist does a second check into the
                # hacks table to see if it exists in the mapping.

                imported_files = 0
                n_files = rconn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

                for file_id, timestamp in rconn.execute("SELECT id, timestamp FROM files"):

                    # file_id is an integer value but stored in a TEXT field, of course.
                    file_id = int(file_id)

                    path = "files/{}_files/{}".format(room_token, file_id)
                    try:
                        size = os.path.getsize(path)
                    except Exception as e:
                        logger.warn(
                            "Error accessing file {} ({}); skipping import of this upload".format(
                                path, e
                            )
                        )
                        continue

                    if timestamp > 10000000000:
                        logger.warn(
                            "- file {} has nonsensical timestamp {}; "
                            "importing it with current time".format(path, timestamp)
                        )
                        timestamp = time.time()

                    cur.execute(
                        """
                        INSERT INTO files (room, size, uploaded, expiry, path)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            room_id,
                            size,
                            timestamp,
                            timestamp + 86400 * config.UPLOAD_DEFAULT_EXPIRY_DAYS,
                            path,
                        ),
                    )
                    new_id = cur.lastrowid

                    cur.execute(
                        "INSERT INTO file_id_hacks (room, old_file_id, file) VALUES (?, ?, ?)",
                        (room_id, file_id, new_id),
                    )
                    imported_files += 1

                    if imported_files % 1000 == 0:
                        logger.info("- ... imported {}/{} files".format(imported_files, n_files))

                if imported_files > 0:
                    used_file_hacks = True

                logger.info("- migrated {} files".format(imported_files))

                # There's also a potential room image, which is just stored on disk and not
                # referenced in the database at all because why bother with proper structure when
                # you can just do random stuff.
                #
                # Unlike the regular files (which will expire in 15 days) this one doesn't expire,
                # so we hard link it into the new uploads directory so that (after 15 days) the old
                # dirs can be cleared out without deleting it.  (There is a potential that the old
                # one remains if the room image gets replaced, but since this is one image per room,
                # a few temporarily forgotten room images left around isn't a big deal).
                #
                # (Unlike regular attachments we don't need a file hack row because the room image
                # is not reference by id from existing clients.)

                room_image_path = "files/" + room_token
                old_stat = None
                try:
                    old_stat = os.stat(room_image_path, follow_symlinks=False)
                except Exception:
                    pass
                if old_stat is not None:
                    files_dir = "uploads/" + room_token
                    os.makedirs(files_dir, exist_ok=True)

                    cur.execute(
                        """
                        INSERT INTO files (room, size, uploaded, expiry, path)
                        VALUES (?, ?, ?, NULL, ?)
                        """,
                        (
                            room_id,
                            os.path.getsize(room_image_path),
                            os.path.getmtime(room_image_path),
                            'tmp',
                        ),
                    )

                    file_id = cur.lastrowid
                    new_path = "uploads/{}/{}_(imported_room_image)".format(room_token, file_id)
                    if os.path.exists(new_path):
                        os.remove(new_path)
                    os.link(room_image_path, new_path)
                    cur.execute("UPDATE files SET path = ? WHERE id = ?", (new_path, file_id))
                    cur.execute("UPDATE rooms SET image = ? WHERE id = ?", (file_id, room_id))
                    logger.info("- migrated room image")
                else:
                    logger.info("- no room image")

                # Banned users.  These are just dumped in a table called "block_list" with just a
                # "public_key" TEXT field containing the session id.

                imported_bans = 0
                for (session_id,) in rconn.execute("SELECT public_key FROM block_list"):
                    cur.execute(ins_user, (session_id,))
                    cur.execute(
                        """
                        INSERT INTO user_permission_overrides (room, user, banned)
                            VALUES (?, (SELECT id FROM users WHERE session_id = ?), TRUE)
                        ON CONFLICT (room, user) DO UPDATE SET banned = TRUE
                        """,
                        (room_id, session_id),
                    )
                    imported_bans += 1

                # Moderators.  Since the older version didn't have the concept of moderators and
                # admins, old moderators had all the permissions that new admins have, so import
                # them all as admins.

                imported_mods = 0
                for (session_id,) in rconn.execute("SELECT public_key from moderators"):
                    cur.execute(ins_user, (session_id,))
                    cur.execute(
                        """
                        INSERT INTO user_permission_overrides
                            (room, user, read, write, upload, moderator, admin)
                        VALUES (
                            ?,
                            (SELECT id FROM users WHERE session_id = ?),
                            TRUE, TRUE, TRUE, TRUE, TRUE)
                        ON CONFLICT (room, user) DO UPDATE SET banned = FALSE,
                            read = TRUE, write = TRUE, upload = TRUE, moderator = TRUE, admin = TRUE
                        """,
                        (room_id, session_id),
                    )
                    imported_mods += 1

                # User activity.  For some reason, unlike all the other timestamps in the database,
                # the timestamp here is stored in milliseconds.
                imported_activity, imported_active = 0, 0

                # Don't import rows we're going to immediately prune:
                import_cutoff = time.time() - config.ROOM_ACTIVE_PRUNE_THRESHOLD * 86400
                active_cutoff = time.time() - config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400
                n_activity = rconn.execute(
                    "SELECT COUNT(*) FROM user_activity WHERE last_active > ?", (import_cutoff,)
                ).fetchone()[0]

                for session_id, last_active in rconn.execute(
                    """
                    SELECT public_key, last_active
                    FROM user_activity
                    WHERE last_active > ? AND public_key IS NOT NULL
                    """,
                    (import_cutoff,),
                ):

                    cur.execute(ins_user, (session_id,))
                    cur.execute(
                        """
                        INSERT INTO room_users (room, user, last_active)
                            VALUES (?, (SELECT id FROM users WHERE session_id = ?), ?)
                        ON CONFLICT (room, user) DO UPDATE
                            SET last_active = excluded.last_active
                            WHERE excluded.last_active > last_active
                        """,
                        (room_id, session_id, last_active),
                    )
                    cur.execute(
                        """
                        UPDATE users SET last_active = ?1 WHERE session_id = ?2 AND last_active < ?1
                        """,
                        (last_active, session_id),
                    )

                    if last_active >= active_cutoff:
                        imported_active += 1
                    imported_activity += 1
                    if imported_activity % 5000 == 0:
                        logger.info(
                            "- ... imported {}/{} user activity records ({} active)".format(
                                imported_activity, n_activity, imported_active
                            )
                        )

                logger.warn(
                    "Imported room {}: "
                    "{} messages, {} files, {} moderators, {} bans, {} users ({} active)".format(
                        room_token,
                        imported_msgs,
                        imported_files,
                        imported_mods,
                        imported_bans,
                        imported_activity,
                        imported_active,
                    )
                )

                total_msgs += imported_msgs
                total_files += imported_files
                total_rooms += 1

        if not used_room_hacks:
            cur.execute("DROP TABLE room_import_hacks")
        if not used_file_hacks:
            cur.execute("DROP TABLE file_id_hacks")

    logger.warn(
        "Import finished!  Imported {} messages/{} files in {} rooms".format(
            total_msgs, total_files, total_rooms
        )
    )

    try:
        os.rename("database.db", "old-database.db")
    except Exception as e:
        logger.warn("Failed to rename database.db -> old-database.db: {}".format(e))
