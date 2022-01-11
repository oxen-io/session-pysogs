import pytest

from sogs import config

config.DB_URL = 'defer-init'

from sogs import web  # noqa: E402
from sogs.model.room import Room  # noqa: E402
from sogs.model.user import SystemUser  # noqa: E402


def pytest_addoption(parser):
    parser.addoption(
        "--sql-tracing", action="store_true", default=False, help="Log all SQL queries"
    )


db_counter_ = 0


@pytest.fixture
def db(request):
    """
    Import this fixture to get a wiped, re-initialized database for db.engine.  The actual fixture
    value is the db module itself (so typically you don't import it at all but instead get it
    through this fixture, which also creates an empty db for you).
    """

    trace = request.config.getoption("--sql-tracing")

    from sogs import db as db_

    global db_counter_
    db_counter_ += 1
    sqlite_uri = f'file:sogs_testdb{db_counter_}?mode=memory&cache=shared'

    web.app.logger.warning(f"using sqlite {sqlite_uri}")

    def sqlite_connect():
        import sqlite3

        web.app.logger.warning(f"connecting to {sqlite_uri}")
        return sqlite3.connect(sqlite_uri, uri=True)

    db_._init_engine("sqlite://", creator=sqlite_connect, echo=trace)

    web.appdb = db_.get_conn()

    yield db_

    web.app.logger.warning("closing db")
    web.appdb.close()


@pytest.fixture
def room(db):
    """
    Creates a basic test room, because many, many tests need this.  (Also implicitly pulls in the db
    fixture for a fresh database).
    """

    return Room.create('test-room', name='Test room', description='Test suite testing room')


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


web.app.config.update({'TESTING': True})
