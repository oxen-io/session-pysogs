import pytest

from sogs import config

config.DB_URL = 'defer-init'
config.REQUIRE_BLIND_KEYS = False

from sogs import web  # noqa: E402
from sogs.model.room import Room  # noqa: E402
from sogs.model.user import SystemUser  # noqa: E402

import sogs.omq  # noqa: E402

import sqlalchemy  # noqa: E402

import atexit, shutil, tempfile  # noqa: E402 E401

_tempdirs = set()

sogs.omq.test_suite = True


def pgsql_url(arg):
    if not arg.startswith('postgresql:'):
        raise ValueError("Invalid postgresql url; see SQLAlchemy postgresql docs")
    return arg


def pytest_addoption(parser):
    parser.addoption(
        "--sql-tracing", action="store_true", default=False, help="Log all SQL queries"
    )
    parser.addoption(
        "--pgsql", type=pgsql_url, help="Use the given postgresql database url for testing"
    )
    parser.addoption(
        "--pgsql-no-drop-schema",
        action="store_true",
        default=False,
        help="Don't clean up the final test schema; typically used with --maxfail=1",
    )


@pytest.fixture
def client():
    """Yields an flask test client for the app that can be used to make test requests"""

    with web.app.test_client() as client:
        yield client


db_counter_ = 0


# Under postgresql & sqlalchemy 1.3.x we have to hack around a bit to get sqlalchemy to properly use
# the pgsql search_path, most notably passing it in the connect string, but that fails if the schema
# doesn't already exist; thus we establish an extra connection to the database to create it at
# session startup and tear it down at session end.
#
# Under higher sqlalchemy this simply provides the pgsql url, and under sqlite this returns None.
@pytest.fixture(scope="session")
def pgsql(request):
    pgsql = request.config.getoption("--pgsql")
    if pgsql:
        if sqlalchemy.__version__.startswith("1.3."):
            import psycopg2

            conn = psycopg2.connect(pgsql)
            with conn.cursor() as cur:
                cur.execute("CREATE SCHEMA IF NOT EXISTS sogs_tests")
            conn.commit()

            pgsql_w_schema = pgsql + ('&' if '?' in pgsql else '?')
            pgsql_w_schema += 'options=--search_path%3Dsogs_tests%2Cpublic'

            yield pgsql_w_schema

            if not request.config.getoption("--pgsql-no-drop-schema"):
                print("DROPPING SCHEMA")
                with conn.cursor() as cur:
                    cur.execute("DROP SCHEMA sogs_tests CASCADE")
                conn.commit()

            conn.close()
        else:
            yield pgsql
    else:
        yield None


@pytest.fixture
def db(request, pgsql):
    """
    Import this fixture to get a wiped, re-initialized database for db.engine.  The actual fixture
    value is the db module itself (so typically you don't import it at all but instead get it
    through this fixture, which also creates an empty db for you).
    """
    d = tempfile.mkdtemp(prefix='tmp_pysogs')
    _tempdirs.add(d)
    config.UPLOAD_PATH = d
    trace = request.config.getoption("--sql-tracing")

    from sogs import db as db_

    global db_counter_
    db_counter_ += 1

    if pgsql:
        web.app.logger.warning(f"using postgresql {pgsql}")

        first = True

        def pg_setup_schema():
            # Run everything in a separate schema that we can easily drop when done

            @sqlalchemy.event.listens_for(db_.engine, "connect", insert=True)
            def setup_schema(dbapi_connection, connection_record):
                existing_autocommit = dbapi_connection.autocommit
                dbapi_connection.autocommit = True

                cursor = dbapi_connection.cursor()
                nonlocal first
                if first:
                    cursor.execute("DROP SCHEMA IF EXISTS sogs_tests CASCADE")
                    first = False
                cursor.execute("CREATE SCHEMA IF NOT EXISTS sogs_tests")
                cursor.execute("SET search_path TO sogs_tests, public")
                cursor.close()

                dbapi_connection.autocommit = existing_autocommit

        db_.init_engine(pgsql, echo=trace, sogs_preinit=pg_setup_schema)

    else:
        sqlite_uri = f'file:sogs_testdb{db_counter_}?mode=memory&cache=shared'

        web.app.logger.warning(f"using sqlite {sqlite_uri}")

        def sqlite_connect():
            import sqlite3

            web.app.logger.warning(f"connecting to {sqlite_uri}")
            return sqlite3.connect(sqlite_uri, uri=True)

        db_.init_engine("sqlite://", creator=sqlite_connect, echo=trace)

    db_.database_init()

    web.appdb = db_.get_conn()

    yield db_

    web.app.logger.warning("closing db")
    if (
        pgsql
        and not sqlalchemy.__version__.startswith("1.3.")
        and not request.config.getoption("--pgsql-no-drop-schema")
    ):
        web.app.logger.critical("DROPPING SCHEMA")
        db_.query("DROP SCHEMA sogs_tests CASCADE")

    web.appdb.close()


@pytest.fixture
def room(db):
    """
    Creates a basic test room, because many, many tests need this.  (Also implicitly pulls in the db
    fixture for a fresh database).
    """

    return Room.create('test-room', name='Test room', description='Test suite testing room')


@pytest.fixture
def room2(db):
    """
    Creates a test room, typically used with `room` when two separate rooms are needed.  Note that
    `mod` and `admin` (if used) are only a mod and admin of `room`, not `room2`
    """

    return Room.create('room2', name='Room 2', description='Test suite testing room2')


@pytest.fixture
def user(db):
    """
    Generates an ordinary user without any special privileges.  Returns a subclass of a model.User
    that also has key signing methods.
    """
    import user

    return user.User()


@pytest.fixture
def user2(db):
    """Same as user; used (along with user) when you want two distinct regular users"""
    import user

    return user.User()


@pytest.fixture
def mod(room):
    """Creates a user who has moderator (but not admin) permission in `room`"""
    import user

    u = user.User()
    room.set_moderator(u, added_by=SystemUser())
    return u


@pytest.fixture
def admin(room):
    """Creates a user who has admin permission in `room`"""
    import user

    u = user.User()
    room.set_moderator(u, added_by=SystemUser(), admin=True)
    return u


@pytest.fixture
def global_admin(db):
    """Creates a user who has (hidden) global admin permissions"""
    import user

    u = user.User()
    u.set_moderator(added_by=SystemUser(), admin=True)
    return u


@pytest.fixture
def global_mod(db):
    """Creates a user who has (hidden) global moderator permissions"""
    import user

    u = user.User()
    u.set_moderator(added_by=SystemUser())
    return u


@pytest.fixture
def banned_user(db):
    import user

    u = user.User()
    u.ban(banned_by=SystemUser())
    return u


@pytest.fixture
def blind15_user(db):
    import user

    return user.User(blinded15=True)


@pytest.fixture
def blind15_user2(db):
    import user

    return user.User(blinded15=True)


@pytest.fixture
def blind25_user(db):
    import user

    return user.User(blinded25=True)


@pytest.fixture
def blind25_user2(db):
    import user

    return user.User(blinded25=True)


@pytest.fixture
def no_rate_limit():
    """Disables post rate limiting for the test"""
    import sogs.model.room as mroom

    saved = (mroom.rate_limit_size, mroom.rate_limit_interval)
    mroom.rate_limit_size, mroom.rate_limit_interval = None, None
    yield None
    mroom.rate_limit_size, mroom.rate_limit_interval = saved


web.app.config.update({'TESTING': True})

atexit.register(lambda: [shutil.rmtree(d) for d in _tempdirs])
