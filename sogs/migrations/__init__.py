import logging
import coloredlogs

from .. import config

from . import (
    import_hacks,
    message_details_deleter,
    message_views,
    new_columns,
    new_tables,
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
        import_hacks,
        seqno_etc,
        message_views,
        user_perm_futures,
    ):
        changes = False
        with db.transaction(conn):
            changes = migration.migrate(conn)
        if changes:
            db.metadata.clear()
            db.metadata.reflect(bind=db.engine, views=True)


#        migrate_v01x,
#        add_new_tables,
#        add_new_columns,
#        create_message_details_deleter,
#        check_for_hacks,
#        seqno_etc_updates,
#        update_message_views,
#        user_perm_future_updates,

#        add_accessible_perm_bit,
#    ):
