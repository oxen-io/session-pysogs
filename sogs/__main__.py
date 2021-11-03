from argparse import ArgumentParser as AP

from . import db

ap = AP()
ap.add_argument('--add', action='store_const', default=False, const=True)
ap.add_argument('--remove', action='store_const', default=False, const=True)
ap.add_argument('--admin', type=str)
ap.add_argument('--mod', type=str)
ap.add_argument('--room', type=str)

args = ap.parse_args()
with db.pool as conn:
    if args.add:
        if args.room:
            conn.execute(
                "INSERT INTO rooms(token, name, description) VALUES(?1, ?1, ?1)", [args.room]
            )
        if args.mod:
            conn.execute(
                "INSERT INTO users(session_id, moderator, visible_mod) VALUES(?, TRUE, TRUE)",
                [args.mod],
            )
        if args.admin:
            conn.execute(
                "INSERT INTO users(session_id, moderator, admin) VALUES(?, TRUE, TRUE)",
                [args.admin],
            )
    if args.remove:
        if args.room:
            conn.execute("DELETE FROM rooms WHERE token = ?", [args.room])
        if args.mod:
            conn.execute(
                "UPDATE users WHERE session_id = ? SET moderator=FALSE visible_mod=FALSE",
                [args.mod],
            )
        if args.admin:
            conn.execute("UPDATE users WHERE session_id = ? SET admin=FALSE", [args.mod])
