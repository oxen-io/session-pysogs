from ..web import app
from .legacy import legacy as legacy_endpoints
from .general import general as general_endpoints
from .onion_request import onion_request as onion_request_endpoints
from .rooms import rooms as rooms_endpoints
from .messages import messages as messages_endpoints
from .users import users as users_endpoints
from .dm import dm as dm_endpoints
from .views import views as views_endpoints

app.register_blueprint(dm_endpoints)
app.register_blueprint(rooms_endpoints)
app.register_blueprint(messages_endpoints)
app.register_blueprint(users_endpoints)
app.register_blueprint(general_endpoints)
app.register_blueprint(onion_request_endpoints)
app.register_blueprint(legacy_endpoints)
app.register_blueprint(views_endpoints)
