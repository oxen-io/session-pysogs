With the server running in the background (e.g. using systemd), you can run the following commands to perform various operations:

| Command                                 | Effect                            |
| --------------------------------------- |:---------------------------------:|
| `--add-room room_id room_name`          | to add a room                     |
| `--delete-room room_id`                 | to delete a room                  |
| `--add-moderator public_key room_id`    | to add a moderator to a room      |
| `--delete-moderator public_key room_id` | to delete a moderator from a room |
| `--print-url`                           | to print your server's URL        |

The open group server binary is normally located in `/usr/bin`, so to e.g. execute the `--print-url` command you'd run:

```
/usr/bin/session-open-group-server --print-url
```
