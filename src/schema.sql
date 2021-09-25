
PRAGMA journal_mode=WAL;

BEGIN;

CREATE TABLE rooms (
    id INTEGER NOT NULL PRIMARY KEY, /* internal database id of the room */
    token TEXT NOT NULL UNIQUE COLLATE NOCASE, /* case-insensitive room identifier used in URLs, etc. */
    name TEXT NOT NULL, /* Publicly visible room name */
    image INTEGER REFERENCES files(id) ON DELETE SET NULL,
    created FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    pinned INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    updates INTEGER NOT NULL DEFAULT 0, /* +1 for each new message, edit or deletion */
    read BOOLEAN NOT NULL DEFAULT TRUE, /* Whether users can read by default */
    write BOOLEAN NOT NULL DEFAULT TRUE, /* Whether users can post by default */
    upload BOOLEAN NOT NULL DEFAULT TRUE, /* Whether file uploads are allowed */
    CHECK(token NOT GLOB '*[^a-zA-Z0-9_-]*')
);
CREATE INDEX rooms_token ON rooms(token);

CREATE TABLE messages (
    id INTEGER NOT NULL PRIMARY KEY,
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id),
    posted FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    edited FLOAT,
    updated INTEGER NOT NULL DEFAULT 0, /* set to the room's `updates` counter when posted/edited/deleted */
    data BLOB, /* Actual message content; set to null to delete a message */
    signature BLOB /* Signature of `data` by `public_key`; set to null when deleting a message */
);
CREATE INDEX messages_room ON messages(room, posted);
CREATE INDEX messages_updated ON messages(room, updated);
CREATE INDEX messages_id ON messages(room, id);

CREATE TABLE message_history (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    replaced FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch when this historic value was replaced by an edit or deletion */
    data TEXT NOT NULL, /* the content prior to the update/delete */
    signature BLOB NOT NULL /* signature prior to the update/delete */
);
CREATE INDEX message_history_message ON message_history(message);
CREATE INDEX message_history_replaced ON message_history(replaced);

-- Trigger to increment a room's `updates` counter and assign it to the messages `updated` field for
-- new messages.
CREATE TRIGGER messages_insert_counter AFTER INSERT ON messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET updates = updates + 1 WHERE id = NEW.room;
    UPDATE messages SET updated = (SELECT updates FROM rooms WHERE id = NEW.room);
END;

-- Trigger to record the old value into message_history whenever data is updated, and update the
-- room's `updates` counter so that clients can query to learn about the update.
CREATE TRIGGER messages_insert_history AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NOT OLD.data
BEGIN
    INSERT INTO message_history (message, data, signature) VALUES (NEW.id, OLD.data, OLD.signature);
    UPDATE rooms SET updates = updates + 1 WHERE id = NEW.room;
    UPDATE messages SET updated = (SELECT updates FROM rooms WHERE id = NEW.room);
END;

-- Trigger to remove the room's pinned message when that message is deleted
CREATE TRIGGER messages_unpin_on_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NULL
BEGIN
    UPDATE rooms SET pinned = NULL WHERE id = OLD.room AND pinned = OLD.id;
END;

-- Trigger to handle moving a message from one room to another; we reset the posted time to now, and
-- reset the updated value to the new room's value so that the moved message is treated as a brand new message in
-- the new room.  We also clear the message as the pinned message from the moved-from room.
-- FIXME TODO: this isn't right because the old room won't have any record of it being moved, and so
-- clients won't know that they should remove it.  Perhaps instead we should implement moving as a
-- delete + reinsert, via a INSTEAD OF trigger.
/*
CREATE TRIGGER message_mover AFTER UPDATE OF room ON messages
FOR EACH ROW WHEN NEW.room != OLD.room
BEGIN
    UPDATE messages SET posted = ((julianday('now') - 2440587.5)*86400.0), updated = FALSE
        WHERE messages.id = NEW.id;
    UPDATE rooms SET pinned = NULL WHERE id = OLD.room AND pinned = OLD.id;
END;
*/

CREATE TABLE files (
    id INTEGER NOT NULL PRIMARY KEY,
    room INTEGER REFERENCES rooms(id) ON DELETE SET NULL,
    uploader INTEGER REFERENCES users(id),
    size INTEGER NOT NULL,
    uploaded FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    expiry FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5 + 15.0)*86400.0), /* unix epoch */
    filename TEXT, /* user-provided filename */
    path TEXT NOT NULL /* path on disk */
);
CREATE INDEX files_room ON files(room);
CREATE INDEX files_expiry ON files(expiry);
-- When we delete a room all its files will have room set to NULL but we *also* need to make them
-- for immediate expiry so that the file pruner finds them to clean them up at the next cleanup
-- check.
CREATE TRIGGER room_expire_roomless AFTER UPDATE OF room ON files
FOR EACH ROW WHEN NEW.room IS NULL
BEGIN
    UPDATE files SET expiry = 0.0 WHERE id = NEW.id;
END;

CREATE TABLE users (
    id INTEGER NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE,
    created FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    last_active FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    banned BOOLEAN NOT NULL DEFAULT FALSE, /* true = globally banned from all rooms */
    moderator BOOLEAN NOT NULL DEFAULT FALSE, /* true = moderator of all rooms, and can add global bans */
    admin BOOLEAN NOT NULL DEFAULT FALSE, /* true = admin of all rooms, and can appoint global bans/mod/admins */
    visible_mod BOOLEAN NOT NULL DEFAULT FALSE, /* if true this user (if a moderator) is included in the list of each room's public moderators *unless* specifically listed as a hidden moderator of a room */
    CHECK(NOT (banned AND (moderator OR admin))) /* someone cannot be banned *and* a moderator at the same time */
);
CREATE INDEX users_last_active ON users(last_active);
-- Create a trigger to maintain the implication "admin implies moderator"
CREATE TRIGGER user_update_admins_are_mods AFTER UPDATE OF moderator, admin ON users
FOR EACH ROW WHEN NEW.admin AND NOT NEW.moderator
BEGIN
    UPDATE users SET moderator = TRUE WHERE id = NEW.id;
END;
CREATE TRIGGER user_insert_admins_are_mods AFTER INSERT ON users
FOR EACH ROW WHEN NEW.admin AND NOT NEW.moderator
BEGIN
    UPDATE users SET moderator = TRUE WHERE id = NEW.id;
END;



CREATE TABLE room_users (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_active FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    PRIMARY KEY(room, user)
) WITHOUT ROWID;
CREATE INDEX room_users_room_activity ON room_users(room, last_active);
CREATE INDEX room_users_activity ON room_users(last_active);

-- Stores permissions or restrictions on a user.  Null values (for read/write) mean "user the room's
-- default".
CREATE TABLE user_permission_overrides (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    banned BOOLEAN NOT NULL DEFAULT FALSE, /* If true the user is banned */
    read BOOLEAN, /* If false the user may not fetch messages; null uses room default; true allows reading */
    write BOOLEAN, /* If false the user may not post; null uses room default; true allows posting */
    upload BOOLEAN, /* If false the user may not upload files; null uses room default; true allows uploading */
    moderator BOOLEAN NOT NULL DEFAULT FALSE, /* If true the user may moderate non-moderators */
    admin BOOLEAN NOT NULL DEFAULT FALSE, /* If true the user may moderate anyone (including other moderators and admins) */
    visible_mod BOOLEAN NOT NULL DEFAULT TRUE, /* If true then this user (if a moderator) is included in the list of a room's public moderators */
    PRIMARY KEY(room, user),
    CHECK(NOT (banned AND (moderator OR admin))) /* Mods/admins cannot be banned */
) WITHOUT ROWID;
CREATE INDEX user_permission_overrides_public_mods ON
    user_permission_overrides(room) WHERE moderator OR admin;

-- Create a trigger to maintain the implication "admin implies moderator"
CREATE TRIGGER user_perms_update_admins_are_mods AFTER UPDATE OF moderator, admin ON user_permission_overrides
FOR EACH ROW WHEN NEW.admin AND NOT NEW.moderator
BEGIN
    UPDATE user_permission_overrides SET moderator = TRUE WHERE room = NEW.room AND user = NEW.user;
END;
CREATE TRIGGER user_perms_insert_admins_are_mods AFTER INSERT ON user_permission_overrides
FOR EACH ROW WHEN NEW.admin AND NOT NEW.moderator
BEGIN
    UPDATE user_permission_overrides SET moderator = TRUE WHERE room = NEW.room AND user = NEW.user;
END;

-- Trigger that removes useless empty permission override rows (e.g. after a ban gets removed, and
-- no other permissions roles are set).
CREATE TRIGGER user_perms_empty_cleanup AFTER UPDATE ON user_permission_overrides
FOR EACH ROW WHEN NOT (NEW.banned OR NEW.moderator OR NEW.admin) AND COALESCE(NEW.read, NEW.write, NEW.upload) IS NULL
BEGIN
    DELETE from user_permission_overrides WHERE room = NEW.room AND user = NEW.user;
END;

-- Triggers than remove a user from `room_users` when they are banned from the room
CREATE TRIGGER room_users_remove_banned AFTER UPDATE OF banned ON user_permission_overrides
FOR EACH ROW WHEN NEW.banned
BEGIN
    DELETE FROM room_users WHERE room = NEW.room AND user = NEW.user;
END;

-- View of permissions; for users with an entry in user_permissions we use those values; for null
-- values or no user_permissions entry we return the room's default read/write values (and false for
-- the other fields).
CREATE VIEW user_permissions AS
SELECT
    rooms.id AS room,
    users.id AS user,
    users.session_id,
    CASE WHEN users.banned THEN TRUE ELSE COALESCE(user_permission_overrides.banned, FALSE) END AS banned,
    COALESCE(user_permission_overrides.read, rooms.read) AS read,
    COALESCE(user_permission_overrides.write, rooms.write) AS write,
    COALESCE(user_permission_overrides.upload, rooms.upload) AS upload,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.moderator, FALSE) END AS moderator,
    CASE WHEN users.admin THEN TRUE ELSE COALESCE(user_permission_overrides.admin, FALSE) END AS admin,
    -- room_moderator will be TRUE if the user is specifically listed as a moderator of the room
    COALESCE(user_permission_overrides.moderator OR user_permission_overrides.admin, FALSE) AS room_moderator,
    -- global_moderator will be TRUE if the user is a global moderator/admin (note that this is
    -- *not* exclusive of room_moderator: a moderator/admin could be listed in both).
    COALESCE(users.moderator OR users.admin, FALSE) as global_moderator,
    -- visible_mod will be TRUE if this mod is a publicly viewable moderator of the room
    CASE
        WHEN user_permission_overrides.moderator OR user_permission_overrides.admin THEN user_permission_overrides.visible_mod
        WHEN users.moderator OR users.admin THEN users.visible_mod
        ELSE FALSE
    END AS visible_mod
FROM
    users JOIN rooms LEFT OUTER JOIN user_permission_overrides ON
        users.id = user_permission_overrides.user AND rooms.id = user_permission_overrides.room;

-- Scheduled changes to user permissions.  For example, to implement a 2-day timeout you would set
-- their user_permissions.write to false, then set a `write = true` entry with a +2d timestamp here.
-- Or to implement a join delay you could set room defaults to false then insert a value here to be
-- applied after a delay.
CREATE TABLE user_permission_futures (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at FLOAT NOT NULL, /* when the change should take effect (unix epoch) */
    read BOOLEAN, /* Set this value @ at, if non-null */
    write BOOLEAN, /* Set this value @ at, if non-null */
    upload BOOLEAN, /* Set this value @ at, if non-null */
    PRIMARY KEY(room, user)
) WITHOUT ROWID;
CREATE INDEX user_permissions_future_at ON user_permission_futures(at);

COMMIT;
