import logging
import coloredlogs

from .. import config

from . import (
    blind25,
    file_message,
    fix_info_update_triggers,
    import_hacks,
    message_views,
    new_columns,
    new_tables,
    reactions,
    room_accessible,
    room_moderators,
    seqno_creation,
    seqno_etc,
    user_permissions,
    user_perm_futures,
    v_0_1_x,
)

logger = logging.getLogger(__name__)
coloredlogs.install(milliseconds=True, isatty=True, logger=logger, level=config.LOG_LEVEL)


def migrate(conn, *, check_only=False):
    """
    Perform database migrations/updates/etc.  If check_only is given then we only check whether
    migrations are needed, raising a RuntimeError (without performing any migrations) if we find
    any.
    """

    from .. import db

    any_changes = False

    # NB: migration order here matters; some later migrations require earlier migrations
    for migration in (
        v_0_1_x,
        new_tables,
        new_columns,
        seqno_etc,
        reactions,
        seqno_creation,
        blind25,
        message_views,
        user_perm_futures,
        room_accessible,
        room_moderators,
        user_permissions,
        file_message,
        fix_info_update_triggers,
        import_hacks,
    ):
        changes = False
        if check_only:
            migration.migrate(conn, check_only=True)
        else:
            with db.transaction(conn):
                changes = migration.migrate(conn, check_only=False)
            if changes:
                db.metadata.clear()
                db.metadata.reflect(bind=db.engine, views=True)
                any_changes = True

    return any_changes
