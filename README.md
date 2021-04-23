![example workflow](https://github.com/nielsandriesse/session-open-group-server/actions/workflows/check.yml/badge.svg)

[API Documentation](https://github.com/nielsandriesse/session-open-group-server/blob/main/DOCUMENTATION.md)

[CLI Reference](https://github.com/nielsandriesse/session-open-group-server/blob/main/CLI.md)

Want to build from source? See [BUILDING.md](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md).

## Installation Instructions

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

- make yourself a moderator using the following command: `/usr/bin/session-open-group-server --add-moderator {public_key} {room_id}`
- add your room on Session desktop using the URL printed earlier
- use Session desktop to upload a picture for your room

Or

- Upload a JPG to your VPS
- Put it in `/var/lib/session-open-group-server/files`
- Rename it to `{room_id}` (no file extension)

## Customization

The default options the Session open group server runs with should be fine in most cases, but if you like you can run on a custom port or host, specify the path to the X25519 key pair you want to use, etc. To do this, simply add [the right arguments](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md#step-3-run-it) to the `ExecStart` line in your systemd service file (normally located under `/etc/systemd/system`) and restart your service using:

```
systemctl restart session-open-group-server.service
```
