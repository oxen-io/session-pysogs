# SOGS administration

Once installed (either via [install-debs.md](deb packages) or [install-uwsgi.md](manually)) SOGS
requires some configuration on the backend in order to add rooms and initial administrators.  When
using the deb-based installation the commands are available through the `sogs` command-line tool.

Note: When running from a session-pysogs project source code directory then you must run `python3
-msogs` from the `session-pysogs` directory instead of the `sogs` command.

The full list of available commands is available by running:

```bash
sogs --help
```

(or `python3 -msogs --help` if running from the source code).

We cover a few of the most common options here, to help get you started.

## Creating a room

To add a room run:

```bash
sogs --add-room TOKEN --name "NAME"
```

Replace `TOKEN` with the address to use in the room URL (which must consist of letters, numbers,
underscores, or dashes), and replace `NAME` with the room name to display in Session.

For example:

```bash
sogs --add-room fishing --name "Fish Talk"
```

If you wish you may also provide a description (though this is not yet displayed in Session):

```bash
sogs --add-room fishing --name "Fish Talk" --description "Three fish, four fish, yellow fish, green fish"
```

The add-room command will, on success, print the details of the new room, such as:

```
Created room fishing:

fishing
=======
Name: Fish Talk
Description: Three fish, four fish, yellow fish, green fish
URL: http://example.net/fishing?public_key=0ea1f6eeb5f16b44ddf0decf5a534ae437de272439e371a5ae04fdb1ba05e524
Messages: 0 (0.0 MB)
Attachments: 0 (0.0 MB)
Active users: 0 (7d), 0 (14d) 0 (30d)
Moderators: 0 admins (0 hidden), 0 moderators (0 hidden)
```

## Add an administrator or moderator to a room

To add an administrator or moderator of a room you use one of the following commands:

```bash
sogs --rooms TOKEN --add-moderators SESSIONID --admin
sogs --rooms TOKEN --add-moderators SESSIONID
```

The difference between an administrator and a moderator is that administrators are permitted to add
and remove administrators/moderators from the room, while moderators cannot.  (Aside from this, both
have full moderation capabilities).

Note that room moderators added from within Session are currently always added as administrators;
this will change in a future Session update to support adding either type.

You can also add one or more session IDs as *global* moderators/administrators by specifying a `+`
for the room.  Global moderators/administrators are considered to be moderators of every room on the
server for both existing rooms and any new future rooms:

```bash
sogs --rooms + --add-moderators SESSIONID --admin --visible
```

You can also add multiple moderators to multiple rooms at once by just adding more room tokens and
session IDs on the command line.  For example:

```bash
sogs --rooms fishing boating --add-moderators SESSIONID_1 SESSIONID_2 SESSIONID_3
```

would add the three session IDs as moderators of both the `fishing` and `boating` rooms.

### Hidden vs visible moderators

Moderators/admins can be either publicly visible (which is the default for room-specific
moderators/admins) or hidden (which is the default for global server moderators/admins).

A hidden moderator still has all the same moderation permissions as a visible moderator, but will
not be displayed to regular (non-moderator) Session users as a room moderator (with a moderator
badge, etc.).

To explicitly control when adding moderators that they should be hidden or visible you can add the
`--visible` or `--hidden` flags when adding a moderator.

## Listing rooms

To list all current rooms use:

```
sogs -L
```

This includes details such as the number of messages, files, active users, and moderators.  If you
also want to list each of the individual moderators in each room add `-v` to the end of the command.

## More!

For other commands, such as listing all global moderators, deleting rooms, and removing
moderators, run:

```
sogs --help
```

for all available command-line options.
