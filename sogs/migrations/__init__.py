import logging
import coloredlogs

from .. import config

from . import (
    import_hacks,
    message_details_deleter,
    message_views,
    new_columns,
    new_tables,
    room_accessible,
    seqno_etc,
    user_perm_futures,
    v_0_1_x,
)

logger = logging.getLogger(__name__)
coloredlogs.install(milliseconds=True, isatty=True, logger=logger, level=config.LOG_LEVEL)


def migrate(conn):
    """Perform database migrations/updates/etc."""

    from .. import db

    # NB: migration order here matters; some later migrations require earlier migrations
    for migration in (
        v_0_1_x,
        new_tables,
        new_columns,
        message_details_deleter,
        seqno_etc,
        message_views,
        user_perm_futures,
        room_accessible,
        import_hacks,
    ):
        changes = False
        with db.transaction(conn):
            changes = migration.migrate(conn)
        if changes:
            db.metadata.clear()
            db.metadata.reflect(bind=db.engine, views=True)
