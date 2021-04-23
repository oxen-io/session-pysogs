![example workflow](https://github.com/nielsandriesse/session-open-group-server/actions/workflows/check.yml/badge.svg)

[API Documentation](https://github.com/nielsandriesse/session-open-group-server/wiki/API-Documentation)

[CLI Reference](https://github.com/nielsandriesse/session-open-group-server/wiki/CLI-Reference)

Want to build from source? See [BUILDING.md](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md).

## Installation Instructions

| Dependency    | Version       |
| ------------- |:-------------:|
| openssl       | 1.1.1         |

### Step 1: Pull in the Session open group server executable:

```
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install session-open-group-server
```

### Step 2: Add a room

Add a room of your choice with the following command:

```
/usr/bin/session-open-group-server --add-room {room_id} {room_name}
```

`room_id` must be lowercase and consist of only letters, numbers and underscores.

### Step 3: Print your server's URL

Print the URL users can use to join rooms on your open group server by running:

```
/usr/bin/session-open-group-server --print-url
```

### Step 4: Add an image for your new room

There are two ways to do this. Either:

• add your room on Session desktop using the URL printed earlier
• make yourself a moderator using the following command: `/usr/bin/session-open-group-server --add-moderator {public_key} {room_id}`
• use Session desktop to upload a picture for your room

Or

• Upload a JPG to your VPS
• Put it in `/var/lib/session-open-group-server/files`
• Rename it to `{room_id}` (no file extension)
