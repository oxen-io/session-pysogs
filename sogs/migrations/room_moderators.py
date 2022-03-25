import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    Adds the room_moderators view, along with a couple other optimizations that came at the same
    time:
    - we drop the user_permissions view (to be recreated in the user_permissions migration code)
    - we drop the user_permission_overrides_public_mods index and recreate a tighter index
    """

    from .. import db

    if 'room_moderators' in db.metadata.tables:
        return False

    logging.warning("DB migration: create room_moderators view")
    if check_only:
        raise DatabaseUpgradeRequired("Create room_moderators view")

    if db.engine.name == "sqlite":
        conn.execute(
            """
CREATE VIEW room_moderators AS
SELECT session_id, mods.* FROM (
    SELECT
        room,
        "user",
        MAX(visible_mod) & 1 AS visible_mod,
        MAX(admin) AS admin,
        MAX(room_moderator) AS room_moderator,
        MAX(global_moderator) AS global_moderator
    FROM (
        SELECT
            room,
            "user",
            CASE WHEN visible_mod THEN 3 ELSE 2 END AS visible_mod,
            admin,
            TRUE AS room_moderator,
            FALSE AS global_moderator
        FROM user_permission_overrides WHERE moderator

        UNION ALL

        SELECT
            rooms.id AS room,
            users.id as "user",
            CASE WHEN visible_mod THEN 1 ELSE 0 END AS visible_mod,
            admin,
            FALSE as room_moderator,
            TRUE as global_moderator
        FROM users CROSS JOIN rooms WHERE moderator
    ) m GROUP BY "user", room
) mods JOIN users on "user" = users.id
"""
        )
    else:  # postgres
        conn.execute(
            """
CREATE VIEW room_moderators AS
SELECT session_id, mods.* FROM (
    SELECT
        room,
        "user",
        CAST(MAX(visible_mod) & 1 AS BOOLEAN) AS visible_mod,
        bool_or(admin) AS admin,
        bool_or(room_moderator) AS room_moderator,
        bool_or(global_moderator) AS global_moderator
    FROM (
        SELECT
            room,
            "user",
            CASE WHEN visible_mod THEN 3 ELSE 2 END AS visible_mod,
            admin,
            TRUE AS room_moderator,
            FALSE AS global_moderator
        FROM user_permission_overrides WHERE moderator

        UNION ALL

        SELECT
            rooms.id AS room,
            users.id as "user",
            CASE WHEN visible_mod THEN 1 ELSE 0 END AS visible_mod,
            admin,
            FALSE as room_moderator,
            TRUE as global_moderator
        FROM users CROSS JOIN rooms WHERE moderator
    ) m GROUP BY "user", room
) mods JOIN users on "user" = users.id
"""
        )

    conn.execute("DROP VIEW IF EXISTS user_permissions")
    conn.execute("DROP INDEX IF EXISTS user_permission_overrides_public_mods")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS user_permission_overrides_mods "
        "ON user_permission_overrides(room) WHERE moderator"
    )

    return True
