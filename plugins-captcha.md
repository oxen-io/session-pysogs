# SOGS CAPTCHA Plugin

Once SOGS has been installed (via [install-uwsgi.md](manually)) and a room has been added (following [administration.md]()), 
you can add the CAPTCHA plugin by following the instructions below.

## Step 1: Disable read and write permissions in your room(s)

You can disable read and write permissions on a single room by running the following command, making sure to replace TOKEN with the room token.

```bash
sogs --room TOKEN --remove-perms "rw"
```
You can disable read and write permissions on multiple rooms by running the following command, making sure to replace TOKENs with the corresponding room tokens.

```bash
sogs --rooms TOKEN TOKEN --remove-perms "rw"
```

You can disable read and write permissions on all rooms by running the following command.

```bash
sogs --rooms='*' --remove-perms "rw"
```
## Step 2: Adjust configuration files

### captcha.ini

Copy the `captcha.ini.sample` file to `captcha.ini`:

```bash
cp captcha.ini.sample captcha.ini
```

Open the file with a text editor of your choice.

```bash
nano captcha.ini
```

Edit the file to change the relevant config options, including sogs_pubkey_hex, sogs_address and name.

```ini
sogs_pubkey_hex = SOGS_PUBLIC_KEY_HEX
sogs_address = OXENMQ_ADDRESS
name = DISPLAY_NAME_OF_PLUGIN
```

### uwsgi-sogs.ini

Open the uwsgi-sogs.ini file.

```bash
nano uwsgi-sogs.ini
```
Uncomment (remove the `;`) on the following line in `uwsgi-sogs.ini`, to ensure the CAPTCHA plugin is run by uwsgi alongside SOGS:

```ini
;mule = sogs.mule:run_captcha
```

### sogs.ini

Open the sogs.ini file.

```bash
nano sogs.ini
```

Uncomment (remove the `;`) on the following line in `sogs.ini`, so the CAPTCHA plugin can communicate with the SOGS:

```ini
;omq_listen = tcp://*:22028
```

## Step 3: Restart SOGS

Restart the SOGS service by running:

```bash
uwsgi uwsgi-sogs.ini
```

If a `chdir` is set in `uwsgi-sogs.ini`, the `NotoColorEmoji.ttf` needs be copied to the `chdir` listed in `uwsgi-sogs.ini`:

```bash
cp sogs/plugins/NotoColorEmoji.ttf [chdir]/NotoColorEmoji.ttf
```