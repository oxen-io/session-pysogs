
PRAGMA journal_mode=WAL;

BEGIN;

CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER NOT NULL PRIMARY KEY, /* internal database id of the room */
    identifier TEXT NOT NULL UNIQUE, /* room identifier used in URLs, etc. */
    name TEXT NOT NULL, /* Publicly visible room name */
    image INTEGER REFERENCES files(id) ON DELETE SET NULL,
    created FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    pinned INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    update_counter INTEGER NOT NULL DEFAULT 0, /* +1 for each edit or deletion */
    read BOOLEAN NOT NULL DEFAULT TRUE, /* Whether users can read by default */
    write BOOLEAN NOT NULL DEFAULT TRUE, /* Whether users can post by default */
    upload BOOLEAN NOT NULL DEFAULT TRUE /* Whether file uploads are allowed */
);
CREATE INDEX IF NOT EXISTS rooms_identifier ON rooms(identifier);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER NOT NULL PRIMARY KEY,
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER REFERENCES users(id),
    posted FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    updated INTEGER, /* set to the room's incremented update counter when edit/deletion occurs */
    data TEXT, /* Actual message content; set to null to delete a message */
    signature BLOB /* Signature of `data` by `public_key`; set to null when deleting a message */
);
CREATE INDEX IF NOT EXISTS messages_room ON messages(room, posted);
CREATE INDEX IF NOT EXISTS messages_updated ON messages(room, updated);

CREATE TABLE message_history (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    replaced FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch when this historic value was replaced by an edit or deletion */
    data TEXT NOT NULL, /* the content prior to the update/delete */
    signature BLOB NOT NULL /* signature prior to the update/delete */
);
CREATE INDEX IF NOT EXISTS message_history_message ON message_history(message);

-- Trigger to record the old value into message_history whenever data is updated, and update the
-- room's update_counter so that clients can query to learn about the update.
CREATE TRIGGER messages_insert_history AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NOT OLD.data
BEGIN
    INSERT INTO message_history (message, data, signature) VALUES (NEW.id, OLD.data, OLD.signature);
    UPDATE rooms SET update_counter = update_counter + 1 WHERE id = NEW.room;
    UPDATE messages SET updated = (SELECT update_counter FROM rooms WHERE id = NEW.room);
END;

-- Trigger to remove the room's pinned message when that message is deleted
CREATE TRIGGER messages_unpin_on_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NULL
BEGIN
    UPDATE rooms SET pinned = NULL WHERE id = OLD.room AND pinned = OLD.id;
END;

-- Trigger to handle moving a message from one room to another; we reset the posted time to now, and
-- reset the updated value to NULL, so that the moved message is treated as a brand new message in
-- the new room.  We also clear the message as the pinned message from the moved-from room.
CREATE TRIGGER message_mover AFTER UPDATE OF room ON messages
FOR EACH ROW WHEN NEW.room != OLD.room
BEGIN
    UPDATE messages SET posted = ((julianday('now') - 2440587.5)*86400.0), updated = FALSE
        WHERE messages.id = NEW.id;
    UPDATE rooms SET pinned = NULL WHERE id = OLD.room AND pinned = OLD.id;
END;

CREATE TABLE IF NOT EXISTS files (
    id INTEGER NOT NULL PRIMARY KEY,
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    uploader INTEGER REFERENCES users(id),
    size INTEGER NOT NULL,
    filename TEXT, /* user-provided filename */
    path TEXT NOT NULL /* path on disk */
);
CREATE INDEX IF NOT EXISTS files_room ON files(room);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER NOT NULL PRIMARY KEY,
    public_key TEXT NOT NULL UNIQUE,
    created FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    last_active FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    banned BOOLEAN NOT NULL DEFAULT FALSE, /* true = globally banned from all rooms */
    moderator BOOLEAN NOT NULL DEFAULT FALSE, /* true = moderator of all rooms, and can add global bans */
    admin BOOLEAN NOT NULL DEFAULT FALSE /* true = admin of all rooms, and can appoint global bans/mod/admins */
);
CREATE INDEX IF NOT EXISTS users_last_active ON users(last_active);

CREATE TABLE IF NOT EXISTS room_users (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_active FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    PRIMARY KEY(room, user)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS room_users_activity ON room_users(room, last_active);

-- Stores permissions or restrictions on a user.  Null values (for read/write) mean "user the room's
-- default".
CREATE TABLE IF NOT EXISTS user_permission_overrides (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    banned BOOLEAN NOT NULL DEFAULT FALSE, /* If true the user is banned */
    read BOOLEAN, /* If false the user may not fetch messages; null uses room default; true allows reading */
    write BOOLEAN, /* If false the user may not post; null uses room default; true allows posting */
    upload BOOLEAN, /* If false the user may not upload files; null uses room default; true allows uploading */
    moderator BOOLEAN NOT NULL DEFAULT FALSE, /* If true the user may moderate non-moderators */
    admin BOOLEAN NOT NULL DEFAULT FALSE, /* If true the user may moderate anyone (including other moderators and admins) */
    PRIMARY KEY(room, user),
    CHECK(NOT (banned AND (moderator OR admin))) /* Mods/admins cannot be banned */
) WITHOUT ROWID;

-- Triggers than remove a user from `room_users` when they are banned from the room
CREATE TRIGGER room_users_remove_banned AFTER UPDATE OF banned ON user_permission_overrides
FOR EACH ROW WHEN NEW.banned
BEGIN
    DELETE FROM room_users WHERE room = NEW.room AND user = NEW.user;
END;

-- View of permissions; for users with an entry in user_permissions we use those values; for null
-- values or no user_permissions entry we return the room's default read/write values (and false for
-- the other fields).  We also apply some other properties: admin implies moderator, and moderator
-- implies read&write.
CREATE VIEW IF NOT EXISTS user_permissions AS
SELECT
    rooms.id AS room,
    users.id AS user,
    users.public_key,
    CASE WHEN users.banned THEN TRUE ELSE COALESCE(user_permission_overrides.banned, FALSE) END AS banned,
    COALESCE(user_permission_overrides.read, rooms.read) AS read,
    COALESCE(user_permission_overrides.write, rooms.write) AS write,
    COALESCE(user_permission_overrides.upload, rooms.upload) AS upload,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.moderator, FALSE) END AS moderator,
    CASE WHEN users.admin THEN TRUE ELSE COALESCE(user_permission_overrides.admin, FALSE) END AS admin
FROM
    users JOIN rooms LEFT OUTER JOIN user_permission_overrides ON
        users.id = user_permission_overrides.user AND rooms.id = user_permission_overrides.room;

-- Scheduled changes to user permissions.  For example, to implement a 2-day timeout you would set
-- their user_permissions.write to false, then set a `write = true` entry with a +2d timestamp here.
-- Or to implement a join delay you could set room defaults to false then insert a value here to be
-- applied after a delay.
CREATE TABLE IF NOT EXISTS user_permission_futures (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at FLOAT NOT NULL, /* when the change should take effect (unix epoch) */
    read BOOLEAN, /* Set this value @ at, if non-null */
    write BOOLEAN, /* Set this value @ at, if non-null */
    upload BOOLEAN, /* Set this value @ at, if non-null */
    PRIMARY KEY(room, user)
) WITHOUT ROWID;
CREATE INDEX user_permissions_future_at ON user_permissions_future(at);

COMMIT;
