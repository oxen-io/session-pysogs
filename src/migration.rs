use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::SystemTime;

use super::handlers;
use super::storage;
use log::{info, warn};
use rusqlite::{params, types::Null, Connection, OpenFlags};

// Performs database migration from v0.1.8 to v0.2.0
pub fn migrate_0_2_0(conn: &mut Connection) -> Result<(), rusqlite::Error> {
    // Old database database.db is a single table database containing just the list of rooms:
    /*
    CREATE TABLE IF NOT EXISTS main (
        id TEXT PRIMARY KEY, -- AKA token
        name TEXT,
        image_id TEXT -- entirely unused.
    )
    */

    // Do the entire import in one transaction so that if anything fails we leave the db empty (so
    // that starting again will try to import again).
    let tx = conn.transaction()?;

    struct Rm {
        token: String,
        name: Option<String>,
    }

    let rooms = Connection::open_with_flags("database.db", OpenFlags::SQLITE_OPEN_READ_ONLY)?
        .prepare("SELECT id, name FROM main")?
        .query_map(params![], |row| Ok(Rm { token: row.get(0)?, name: row.get(1)? }))?
        .collect::<Result<Vec<Rm>, _>>()?;

    warn!("{} rooms to import", rooms.len());

    {
        tx.execute(
            "\
            CREATE TABLE room_import_hacks (
                room INTEGER PRIMARY KEY NOT NULL REFERENCES rooms(id),
                old_message_id_max INTEGER NOT NULL,
                message_id_offset INTEGER NOT NULL
            )",
            [],
        )?;
        let mut used_room_hacks: bool = false;
        let mut ins_room_hack = tx.prepare(
            "INSERT INTO room_import_hacks (room, old_message_id_max, message_id_offset) VALUES (?, ?, ?)")?;

        tx.execute(
            "\
            CREATE TABLE file_id_hacks (
                room INTEGER NOT NULL REFERENCES rooms(id),
                old_file_id INTEGER NOT NULL,
                file INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                PRIMARY KEY(room, old_file_id)
            )",
            [],
        )?;
        let mut used_file_hacks: bool = false;
        let mut ins_file_hack =
            tx.prepare("INSERT INTO file_id_hacks (room, old_file_id, file) VALUES (?, ?, ?)")?;

        let mut ins_room =
            tx.prepare("INSERT INTO rooms (token, name) VALUES (?, ?) RETURNING id")?;

        let mut ins_user = tx.prepare(
            "INSERT INTO users (session_id, last_active) VALUES (?, 0.0) ON CONFLICT DO NOTHING",
        )?;

        let mut ins_msg = tx.prepare(
            "INSERT INTO messages (id, room, user, posted, data, data_size, signature) \
            VALUES (?, ?, (SELECT id FROM users WHERE session_id = ?), ?, ?, ?, ?)",
        )?;

        let mut upd_msg_updated = tx.prepare("UPDATE messages SET updated = ? WHERE id = ?")?;
        let mut upd_room_updates = tx.prepare("UPDATE rooms SET updates = ? WHERE id = ?")?;

        let mut ins_file = tx.prepare(
            "INSERT INTO files (room, size, uploaded, expiry, path) VALUES (?, ?, ?, ?, ?) RETURNING id")?;

        let mut upd_file_path = tx.prepare("UPDATE files SET path = ? WHERE id = ?")?;
        let mut upd_room_image = tx.prepare("UPDATE rooms SET image = ? WHERE id = ?")?;

        let mut ins_room_mod = tx.prepare(
            "INSERT INTO user_permission_overrides (room, user, moderator, admin) VALUES (?, (SELECT id FROM users WHERE session_id = ?), TRUE, TRUE) \
            ON CONFLICT DO UPDATE SET banned = FALSE, read = TRUE, write = TRUE, moderator = TRUE, admin = TRUE")?;
        let mut ins_room_ban = tx.prepare(
            "INSERT INTO user_permission_overrides (room, user, banned) VALUES (?, (SELECT id FROM users WHERE session_id = ?), TRUE) \
            ON CONFLICT DO UPDATE SET banned = TRUE")?;

        let mut ins_room_activity = tx.prepare(
            "INSERT INTO room_users (room, user, last_active) VALUES (?, (SELECT id FROM users WHERE session_id = ?), ?) \
            ON CONFLICT DO UPDATE SET last_active = excluded.last_active WHERE excluded.last_active > last_active")?;
        let mut upd_user_activity = tx.prepare(
            "UPDATE users SET last_active = ?1 WHERE session_id = ?2 AND last_active < ?1",
        )?;

        for room in rooms {
            let room_db_filename = format!("rooms/{}.db", room.token);
            let room_db = Path::new(&room_db_filename);
            if !room_db.exists() {
                warn!("Skipping room {}: {} does not exist", room.token, room_db.display());
                continue;
            }

            info!("Importing room {}...", room.token);

            let room_id =
                ins_room.query_row(params![room.token, room.name], |row| row.get::<_, i64>(0))?;

            let rconn = Connection::open_with_flags(room_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

            /*
            Messages were stored in this:

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY,
                    public_key TEXT,
                    timestamp INTEGER,
                    data TEXT,
                    signature TEXT,
                    is_deleted INTEGER
                );

            where public_key is the session_id (in hex), timestamp is in milliseconds since unix epoch,
            data and signature are in base64 (wtf), data is typically padded from the client (i.e. to
            the next multiple, with lots of 0s on the end).  If the message was deleted then it remains
            here but `is_deleted` is set to 1 (data are signature should be NULL as well, but older
            versions apparently didn't do that), plus we have a row in here:

                CREATE TABLE IF NOT EXISTS deleted_messages (
                    id INTEGER PRIMARY KEY,
                    deleted_message_id INTEGER
                );

            where the `id` of this table is returned to the Session client so that they can query for
            "deletions since [id]".

            This introduces some major complications, though: Session message polling works by
            requesting messages (and deletions) since a given id, but we can't preserve IDs because
            there are guaranteed to be duplicates across rooms.  So we use this room_import_hacks
            defined above to figure this out:

                - if requesting messages in a room since some id  <= old_message_id_max then we
                  actually query messages in the room since id + message_id_offset.

            Deletions doesn't have the same complication because in the new database they use a
            monotonic updates field that we can make conform (for imported rows) to the imported
            deletion ids.
            */

            let mut id_offset: i64 =
                tx.query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM messages", [], |row| {
                    row.get(0)
                })?;
            let mut top_old_id: i64 = -1;
            let mut updated: i64 = 0;
            let mut imported_msgs: i64 = 0;
            struct Msg {
                id: i64,
                session_id: String,
                ts_ms: i64,
                data: Option<String>,
                signature: Option<String>,
                deleted: Option<i64>,
            }
            let n_msgs: i64 =
                rconn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?;
            let mut msg_st = rconn.prepare("\
                SELECT messages.id, public_key, timestamp, data, signature, is_deleted, deleted_messages.id \
                FROM messages LEFT JOIN deleted_messages ON messages.id = deleted_messages.deleted_message_id
                ORDER BY messages.id")?;
            let mut msg_rows = msg_st.query([])?;
            let mut last_id: i64 = -1;
            let mut dupe_dels: i64 = 0;
            while let Some(row) = msg_rows.next()? {
                let msg = Msg {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    ts_ms: row.get(2)?,
                    data: row.get(3)?,
                    signature: row.get(4)?,
                    deleted: if row.get::<_, Option<bool>>(5)?.unwrap_or(false) {
                        Some(row.get(6)?)
                    } else {
                        None
                    },
                };
                if top_old_id == -1 {
                    id_offset -= msg.id;
                }
                if msg.id > top_old_id {
                    top_old_id = msg.id;
                }
                if msg.id == last_id {
                    // There are duplicates in the deleted_messages table (WTF) that can give us
                    // multiple rows through the join, so skip duplicates if they occur.
                    dupe_dels += 1;
                    continue;
                } else {
                    last_id = msg.id;
                }
                ins_user.execute(params![msg.session_id])?;
                if msg.data.is_some() && msg.signature.is_some() && msg.deleted.is_none() {
                    // Regular message

                    // Data was pointlessly store padding, so unpad it:
                    let padded_data = match base64::decode(msg.data.unwrap()) {
                        Ok(d) => d,
                        Err(e) => panic!(
                            "Unexpected data: {} message id={} has non-base64 data ({})",
                            room_db.display(),
                            msg.id,
                            e
                        ),
                    };

                    let data_size = padded_data.len();
                    let data = match padded_data.iter().rposition(|&c| c != 0u8) {
                        Some(last) => &padded_data[0..=last],
                        None => &padded_data,
                    };
                    let sig = match base64::decode(msg.signature.unwrap()) {
                        Ok(d) if d.len() == 64 => d,
                        Ok(_) => panic!(
                            "Unexpected data: {} message id={} has invalid signature",
                            room_db.display(),
                            msg.id
                        ),
                        Err(e) => panic!(
                            "Unexpected data: {} message id={} has non-base64 signature ({})",
                            room_db.display(),
                            msg.id,
                            e
                        ),
                    };
                    ins_msg.execute(params![
                        msg.id + id_offset,
                        room_id,
                        msg.session_id,
                        (msg.ts_ms as f64) / 1000.,
                        data,
                        data_size,
                        sig
                    ])?;
                } else if msg.deleted.is_some() &&
                    // Deleted messages are usually set to the fixed string "deleted" (why not
                    // NULL?) for data and signature, so accept either null or that string if the
                    // other columns indicate a deleted message.
                    (msg.data.is_none() || msg.data.as_ref().unwrap() == "deleted") &&
                    (msg.signature.is_none() || msg.signature.as_ref().unwrap() == "deleted")
                {
                    updated += 1;

                    // Deleted message; we still need to insert a tombstone for it, and copy the
                    // deletion id as the "updated" field.  (We do this with a second query because the
                    // first query is going to trigger an automatic update of the field).

                    ins_msg.execute(params![
                        msg.id + id_offset,
                        room_id,
                        msg.session_id,
                        (msg.ts_ms as f64) / 1000.,
                        Null,
                        Null,
                        Null
                    ])?;
                } else {
                    panic!("Inconsistent message in {} database: message id={} has inconsistent deletion state (data: {}, signature: {}, del row: {})",
                        room_db.display(), msg.id, msg.data.is_some(), msg.signature.is_some(), msg.deleted.is_some());
                }

                upd_msg_updated.execute(params![updated, msg.id + id_offset])?;
                imported_msgs += 1;
                if imported_msgs % 1000 == 0 {
                    info!("- ... imported {}/{} messages", imported_msgs, n_msgs);
                }
            }
            info!(
                "- migrated {} messages, {} duplicate deletions ignored",
                imported_msgs, dupe_dels
            );

            upd_room_updates.execute(params![updated, room_id])?;

            // If we have to offset rowids then make sure the hack table exists and insert our hack.
            if id_offset != 0 {
                used_room_hacks = true;
                ins_room_hack.execute(params![room_id, top_old_id, id_offset])?;
            }

            let mut imported_files: i64 = 0;

            let n_files: i64 =
                rconn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))?;
            // WTF is this id stored as a TEXT?
            struct File {
                id: String,
                ts: i64,
            }
            let mut rows_st = rconn.prepare("SELECT id, timestamp FROM files")?;
            let mut file_rows = rows_st.query([])?;
            while let Some(row) = file_rows.next()? {
                let file = File { id: row.get(0)?, ts: row.get(1)? };
                let old_id = match file.id.parse::<i64>() {
                    Ok(id) => id,
                    Err(e) => {
                        panic!("Invalid fileid '{}' found in {}: {}", file.id, room_db.display(), e)
                    }
                };
                let old_path = format!("files/{}_files/{}", room.token, old_id);
                let size = match fs::metadata(&old_path) {
                    Ok(md) => md.len(),
                    Err(e) => {
                        warn!(
                            "Error accessing file {} ({}); skipping import of this upload",
                            old_path, e
                        );
                        continue;
                    }
                };

                let ts = if file.ts > 10000000000 {
                    warn!(
                        "- file {} has nonsensical timestamp {}; importing it with current time",
                        old_path, file.ts
                    );
                    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64()
                } else {
                    file.ts as f64
                };

                let new_id = ins_file.query_row(
                    params![
                        room_id,
                        size,
                        ts,
                        ts + handlers::UPLOAD_DEFAULT_EXPIRY.as_secs_f64(),
                        old_path
                    ],
                    |row| row.get::<_, i64>(0),
                )?;

                ins_file_hack.execute(params![room_id, old_id, new_id])?;
                imported_files += 1;
                if imported_files % 1000 == 0 {
                    info!("- ... imported {}/{} files", imported_files, n_files);
                }
            }
            if imported_files > 0 {
                used_file_hacks = true;
            }
            info!("- migrated {} files", imported_files);

            // There's also a potential room image, which is just stored on disk and not referenced in
            // the database at all because why not.
            //
            // Unlike the regular files (which will expire in 15 days) this one doesn't expire, so
            // link it into the new uploads directory so that (after 15 days) the old dirs can be
            // cleared out.
            let room_image_path = format!("files/{}", room.token);
            if let Ok(md) = fs::metadata(&room_image_path) {
                let files_dir = format!("uploads/{}", room.token);
                if let Err(e) = std::fs::create_dir_all(&files_dir) {
                    panic!("Unable to mkdir {} for room file storage: {}", files_dir, e);
                }
                let file_id = ins_file.query_row(
                    params![
                        room_id,
                        md.len(),
                        md.mtime() as f64 + md.mtime_nsec() as f64 * 1e-9,
                        Null,
                        "tmp"
                    ],
                    |row| row.get::<_, i64>(0),
                )?;
                let new_image_path = format!("uploads/{}/{}_(unnamed)", room.token, file_id);
                if let Err(e) = fs::hard_link(&room_image_path, &new_image_path) {
                    panic!(
                        "Unable to hard link room image file {} => {}: {}",
                        room_image_path, new_image_path, e
                    );
                }
                upd_file_path.execute(params![new_image_path, file_id])?;
                upd_room_image.execute(params![file_id, room_id])?;
                // Don't need a file hack row because the room image isn't reference by id from
                // existing clients.
                info!("- migrated room image");
            } else {
                info!("- no room image");
            }

            // Banned users.
            let mut imported_bans: i64 = 0;
            let mut ban_st = rconn.prepare("SELECT public_key FROM block_list")?;
            let mut ban_rows = ban_st.query([])?;
            while let Some(row) = ban_rows.next()? {
                let banned_id: String = row.get(0)?;
                ins_user.execute(params![banned_id])?;
                ins_room_ban.execute(params![room_id, banned_id])?;
                imported_bans += 1;
            }

            // Moderators.  Since the older version didn't have the concept of moderators and admins,
            // old moderators had all the permissions that new admins have, so import them all as
            // admins.
            let mut imported_mods: i64 = 0;
            let mut mods_st = rconn.prepare("SELECT public_key from moderators")?;
            let mut mod_rows = mods_st.query([])?;
            while let Some(row) = mod_rows.next()? {
                let mod_id: String = row.get(0)?;
                ins_user.execute(params![mod_id])?;
                ins_room_mod.execute(params![room_id, mod_id])?;
                imported_mods += 1;
            }

            // User activity
            let mut imported_activity: i64 = 0;
            let mut imported_active: i64 = 0;
            // Don't import rows we're going to immediately prune:
            let import_cutoff = (SystemTime::now() - storage::ROOM_ACTIVE_PRUNE_THRESHOLD)
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            let n_activity: i64 = rconn.query_row(
                "SELECT COUNT(*) FROM user_activity WHERE last_active > ?",
                params![import_cutoff],
                |row| row.get(0),
            )?;
            let mut activity_st = rconn.prepare("SELECT public_key, last_active FROM user_activity WHERE last_active > ? AND public_key IS NOT NULL")?;
            let mut act_rows = activity_st.query(params![import_cutoff])?;
            let cutoff = (SystemTime::now() - handlers::ROOM_DEFAULT_ACTIVE_THRESHOLD)
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            while let Some(row) = act_rows.next()? {
                let session_id: String = row.get(0)?;
                let ts: f64 = row.get::<_, i64>(1)? as f64;
                ins_user.execute(params![session_id])?;
                ins_room_activity.execute(params![room_id, session_id, ts])?;
                upd_user_activity.execute(params![ts, session_id])?;
                if ts >= cutoff {
                    imported_active += 1;
                }
                imported_activity += 1;
                if imported_activity % 1000 == 0 {
                    info!(
                        "- ... imported {}/{} user activity records ({} active)",
                        imported_activity, n_activity, imported_active
                    );
                }
            }
            warn!("Imported room {}: {} messages, {} files, {} moderators, {} bans, {} users ({} active)",
                  room.token, imported_msgs, imported_files, imported_mods, imported_bans, imported_activity, imported_active);
        }

        if !used_room_hacks {
            tx.execute("DROP TABLE room_import_hacks", [])?;
        }
        if !used_file_hacks {
            tx.execute("DROP TABLE file_id_hacks", [])?;
        }
    }

    tx.commit()?;

    warn!("Import finished!");

    Ok(())
}
