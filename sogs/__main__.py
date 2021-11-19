from argparse import ArgumentParser as AP, RawDescriptionHelpFormatter
import re
import sys
import sqlite3

from . import db
from . import config
from . import model
from . import crypto

ap = AP(epilog="""

Examples:

    # Add new room 'xyz':
    python3 -msogs --add-room xyz --name 'XYZ Room'

    # Add 2 admins to each of rooms 'xyz' and 'abc':
    python3 -msogs --rooms abc xyz --add-moderators 050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0500112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --admin

     # Add a global moderator visible as a moderator of all rooms:
    python3 -msogs --add-moderators 050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --rooms=+ --visible

     # List room info:
    python3 -msogs -L

""", formatter_class=RawDescriptionHelpFormatter)

actions = ap.add_mutually_exclusive_group()

actions.add_argument('--add-room', help="Add a room with the given token", metavar='TOKEN')
ap.add_argument(
    '--name', help="Set the room's initial name for --add-room; if omitted use the token name"
)
ap.add_argument('--description', help="Specifies the room's initial description for --add-room")
actions.add_argument('--delete-room', help="Delete the room with the given token", metavar='TOKEN')
actions.add_argument(
    '--add-moderators',
    nargs='+',
    metavar='SESSIONID',
    help="Add the given Session ID(s) as a moderator of the room given by --rooms",
)
actions.add_argument(
    '--delete-moderators',
    nargs='+',
    metavar='SESSIONID',
    help="Delete the the given Session ID(s) as moderator and admins of the room given by --rooms",
)
ap.add_argument(
    '--admin',
    action='store_true',
    help="Add the given moderators as admins rather than ordinary moderators",
)
ap.add_argument(
    '--rooms',
    nargs='+',
    metavar='TOKEN',
    help="Room(s) to use when adding/removing moderators/admins. If a single room name of '+' is "
    "given then the user will be added/removed as a global admin/moderator. If a single room name "
    "of '*' is given then the user is added/removed as an admin/moderator from each of the "
    "server's current rooms.",
)
vis_group = ap.add_mutually_exclusive_group()
vis_group.add_argument(
    '--visible',
    action='store_true',
    help="Make an added moderator/admins' status publicly visible. This is the default for room "
    "mods, but not for global mods",
)
vis_group.add_argument(
    '--hidden',
    action='store_true',
    help="Hide the added moderator/admins' status from public users. This is the default for "
    "global mods, but not for room mods",
)
actions.add_argument(
    "--list-rooms", "-L", action='store_true', help="List current rooms and basic stats"
)
actions.add_argument(
    '--list-global-mods', '-M', action='store_true', help="List global moderators/admins"
)
ap.add_argument(
    "--yes", action='store_true', help="Don't prompt for confirmation for some commands, just do it"
)

args = ap.parse_args()


def print_room(room: model.Room):
    msgs, msgs_size = room.messages_size()
    files, files_size = room.attachments_size()

    msgs_size /= 1_000_000
    files_size /= 1_000_000

    active = [room.active_users(x * 86400) for x in (7, 14, 30)]
    m, a, hm, ha = room.get_all_moderators()
    admins = len(a) + len(ha)
    mods = len(m) + len(hm)

    print(
        f"""
{room.token}
{"=" * len(room.token)}
Name: {room.name}
Description: {room.description}
URL: {config.URL_BASE}/{room.token}?public_key={crypto.server_pubkey_hex}
Messages: {msgs} ({msgs_size:.1f} MB)
Attachments: {files} ({files_size:.1f} MB)
Active users: {active[0]} (7d), {active[1]} (14d) {active[2]} (30d)
Moderators: {admins} admins ({len(ha)} hidden), {mods} moderators ({len(hm)} hidden):"""
    )
    for id in a:
        print(f"    - {id} (admin)")
    for id in ha:
        print(f"    - {id} (hidden admin)")
    for id in m:
        print(f"    - {id} (moderator)")
    for id in hm:
        print(f"    - {id} (hidden moderator)")


db.conn = db.sqlite_connect()
if args.add_room:
    if not re.fullmatch(r'[\w-]{1,64}', args.add_room):
        print(
            "Error: room tokens may only contain a-z, A-Z, 0-9, _, and - characters",
            file=sys.stderr,
        )
        sys.exit(1)

    with db.conn as conn:
        try:
            conn.execute(
                "INSERT INTO rooms(token, name, description) VALUES(?, ?, ?)",
                [args.add_room, args.name or args.add_room, args.description],
            )
        except sqlite3.IntegrityError:
            print(f"Error: room '{args.add_room}' already exists!", file=sys.stderr)
            sys.exit(1)
    print(f"Created room {args.add_room}:")
    print_room(model.Room(token=args.add_room))

elif args.delete_room:
    try:
        room = model.Room(token=args.delete_room)
    except model.NoSuchRoom:
        print(f"Error: no such room '{args.delete_room}'", file=sys.stderr)
        sys.exit(1)

    print_room(room)
    if args.yes:
        res = "y"
    else:
        res = input("Are you sure you want to delete this room? [yN] ")
    if res.startswith("y") or res.startswith("Y"):
        with db.conn:
            cur = db.conn.cursor()
            cur.execute("DELETE FROM rooms WHERE token = ?", [args.delete_room])
            count = cur.rowcount
        print("Room deleted.")
    else:
        print("Aborted.")
        sys.exit(2)

elif args.add_moderators:
    if not args.rooms:
        print("Error: --rooms is required when using --add-moderators", file=sys.stderr)
        sys.exit(1)
    for a in args.add_moderators:
        if not re.fullmatch(r'05[A-Fa-f0-9]{64}', a):
            print("Error: '{}' is not a valid session id".format(a), file=sys.stderr)
            sys.exit(1)
    if len(args.rooms) > 1 and ('*' in args.rooms or '+' in args.rooms):
        print(
            "Error: '+'/'*' arguments to --rooms cannot be used with other rooms", file=sys.stderr
        )
        sys.exit(1)
    if args.rooms == ['+']:
        for sid in args.add_moderators:
            u = model.User(session_id=sid)
            u.set_moderator(admin=args.admin, visible=args.visible)
            print(
                "Added {} as {} global {}".format(
                    sid,
                    "visible" if args.visible else "hidden",
                    "admin" if args.admin else "moderator",
                )
            )
    else:
        if args.rooms == ['*']:
            rooms = model.get_rooms()
        else:
            try:
                rooms = [model.Room(token=r) for r in args.rooms]
            except model.NoSuchRoom as nsr:
                print("No such room: '{}'".format(nsr.token), file=sys.stderr)

        for sid in args.add_moderators:
            u = model.User(session_id=sid)
            for room in rooms:
                room.set_moderator(u, admin=args.admin, visible=not args.hidden)
                print(
                    "Added {} as {} {} of {} ({})".format(
                        u.session_id,
                        "hidden" if args.hidden else "visible",
                        "admin" if args.admin else "moderator",
                        room.name,
                        room.token,
                    )
                )

elif args.delete_moderators:
    if not args.rooms:
        print("Error: --rooms is required when using --delete-moderators", file=sys.stderr)
        sys.exit(1)
    for a in args.delete_moderators:
        if not re.fullmatch(r'05[A-Fa-f0-9]{64}', a):
            print("Error: '{}' is not a valid session id".format(a), file=sys.stderr)
            sys.exit(1)
    if len(args.rooms) > 1 and ('*' in args.rooms or '+' in args.rooms):
        print(
            "Error: '+'/'*' arguments to --rooms cannot be used with other rooms", file=sys.stderr
        )
        sys.exit(1)
    if args.rooms == ['+']:
        for sid in args.delete_moderators:
            u = model.User(session_id=sid)
            was_admin = u.global_admin
            if not u.global_admin and not u.global_moderator:
                print("{} was not a global moderator".format(u.session_id))
            else:
                u.remove_moderator()
            print("Removed {} as global {}".format(sid, "admin" if was_admin else "moderator"))
    else:
        if args.rooms == ['*']:
            rooms = model.get_rooms()
        else:
            try:
                rooms = [model.Room(token=r) for r in args.rooms]
            except model.NoSuchRoom as nsr:
                print("No such room: '{}'".format(nsr.token), file=sys.stderr)

        for sid in args.delete_moderators:
            u = model.User(session_id=sid)
            for room in rooms:
                room.remove_moderator(u)
                print(
                    "Removed {} as moderator/admin of {} ({})".format(
                        u.session_id, room.name, room.token
                    )
                )
elif args.list_rooms:
    rooms = model.get_rooms()
    if rooms:
        for room in rooms:
            print_room(room)
    else:
        print("No rooms.")

elif args.list_global_mods:
    m, a, hm, ha = model.get_all_global_moderators()
    admins = len(a) + len(ha)
    mods = len(m) + len(hm)

    print(f"{admins} global admins ({len(ha)} hidden), {mods} moderators ({len(hm)} hidden):")
    for u in a:
        print(f"- {u.session_id} (admin)")
    for u in ha:
        print(f"- {u.session_id} (hidden admin)")
    for u in m:
        print(f"- {u.session_id} (moderator)")
    for u in hm:
        print(f"- {u.session_id} (hidden moderator)")

else:
    print("Error: no action given", file=sys.stderr)
    ap.print_usage()
    sys.exit(1)
