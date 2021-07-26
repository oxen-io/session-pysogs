![example workflow](https://github.com/nielsandriesse/session-open-group-server/actions/workflows/check.yml/badge.svg)

[API Documentation](https://github.com/nielsandriesse/session-open-group-server/blob/main/DOCUMENTATION.md)

[CLI Reference](https://github.com/nielsandriesse/session-open-group-server/blob/main/CLI.md)

Want to build from source? See [BUILDING.md](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md).  
Want to deploy using Docker? See [DOCKER.md](https://github.com/nielsandriesse/session-open-group-server/blob/main/DOCKER.md).

## Installation Instructions

### [Video Guide](https://www.youtube.com/watch?v=D83gKXn6iTI)

**Note:** .debs for the Session Open Group server are currently only available for Ubuntu 20.04.  
For other operating systems, you can either [build from source](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md) or use [Docker](https://github.com/nielsandriesse/session-open-group-server/blob/main/DOCKER.md).

### Step 1: Pull in the Session open group server executable:

```
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install session-open-group-server
sudo chown _loki /var/lib/session-open-group-server -R
```

### Step 2: Add a room

Add a room of your choice with the following command:

```
session-open-group-server --add-room {room_id} {room_name}
```

`room_id` must be lowercase and consist of only letters, numbers and underscores.

For **example**:

```
session-open-group-server --add-room fish FishingAustralia
```

### Step 3: Print your server's URL

Print the URL users can use to join rooms on your open group server by running:

```
session-open-group-server --print-url
```

This will output a result similar to:

```
http://[host_name_or_ip]/[room_id]?public_key=2054fa3271f27ec9e55492c85d022f9582cb4aa2f457e4b885147fb913b9c131
```

You will need to replace `[host_name_or_ip]` with the IP address of your VPS or the domain mapping to your IP address, and `[room_id]` with the ID of one of the rooms you created earlier.

For **example**:

```
http://116.203.217.101/fish?public_key=2054fa3271f27ec9e55492c85d022f9582cb4aa2f457e4b885147fb913b9c131
```

This URL can then be used to join the group inside the Session app.

### Step 4: Make yourself a moderator

Make yourself a moderator using the following command: 

```
session-open-group-server --add-moderator {your_session_id} {room_id}
```

For **example**:

```
session-open-group-server --add-moderator 05d871fc80ca007eed9b2f4df72853e2a2d5465a92fcb1889fb5c84aa2833b3b40 fish
```


### Step 5: Add an image for your new room (Optional)

- Add your room on Session desktop using the URL printed earlier
- Use Session desktop to upload a picture for your room

Or

- Upload a JPG to your VPS
- Put it in `/var/lib/session-open-group-server/files`
- Rename it to `{room_id}` (no file extension)

## Customization

The default options the Session open group server runs with should be fine in most cases, but if you like you can run on a custom port or host, specify the path to the X25519 key pair you want to use, etc. To do this, simply add [the right arguments](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md#step-3-run-it) to the `ExecStart` line in your systemd service file (normally located under `/etc/systemd/system`) and restart your service using:

```
systemctl restart session-open-group-server.service
```
