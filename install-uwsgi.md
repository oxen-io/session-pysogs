# Manual Installation Instructions

## Step 0: Do Not Run PySOGS as root

Do not run pysogs as root.  Some inexperienced system administrators think it is easier to just run
everything as root, without realizing that it is a significant security issue.  Just don't do it.

Instead, use an existing regular user or, even better, create a new regular user just for SOGS.

## Step 1: Clone the PySOGS repo

```bash
git clone https://github.com/oxen-io/session-pysogs -b stable pysogs
cd pysogs
```

This clones the `stable` branch rather than the default `dev` branch.  If you are comfortable with
filing bug reports if problems come up and want to run the development version change `stable` to
`dev`, but keep in mind that things on the dev branch may sometimes be untested and broken.

## Step 2: Install dependencies

PySOGS has a handful of required Python modules and programs.  There are multiple ways to install
these, but the easiest on a recent Ubuntu/Debian system is to install them for the system version of
Python using:

```bash
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install python3-{oxenmq,oxenc,session-util,coloredlogs,uwsgidecorators,flask,cryptography,nacl,pil,protobuf,openssl,qrcode,better-profanity,sqlalchemy,sqlalchemy-utils} uwsgi-plugin-python3
```

If you want to use a postgresql database backend then you will also need the python3-psycopg2
package.  If unsure then stick with the default (sqlite3) database.


## Step 3: Adjust configuration

### sogs.ini

Copy the `sogs.ini.sample` to `sogs.ini`:

```bash
cp sogs.ini.sample sogs.ini
```

Use a text editor like nano to open the file and edit it to change settings as desired.  At a minimum you must uncomment and set the `base_url`
setting to your SOGS URL; this can be a domain name or a public ip address.  Using a domain name is
recommended over a bare IP as it can later be moved to a new host or new ISP, while while a bare IP
cannot.

For example:
```ini
base_url = http://sogs.example.com
```

### uwsgi-sogs.ini

SOGS requires uwsgi to manage processes; sample configurations are available in the contrib/
directory.  For a simple setup listening directly on a public IP/port you can use the standalone
sample configuration:

```bash
cp contrib/uwsgi-sogs-standalone.ini uwsgi-sogs.ini
```

Edit `uwsgi-sogs.ini`, change relevant config settings including chdir, uid, gid.  Other settings
such as http port can also be altered if required.

```ini
chdir = LOCATION_OF_CLONED_DIRECTORY
uid = USER_RUNNING_SOGS
gid = USER_RUNNING_SOGS
http = :UNUSED_PORT
```

Do *not* change the `mount`, `enable-threads`, or `mule` configuration lines.

## Step 4: Run SOGS

Once configured you can temporarily run PySOGS by running the following command while inside the git
repository base directory:

```bash
uwsgi uwsgi-sogs.ini
```

For a more permanent installation, however, you'll want to set up and enable a system service; you
can use [the service file from the debian
packaging](https://github.com/oxen-io/session-pysogs/blob/debian/sid/debian/sogs-standalone.service)
as a starting point.

## Step 5: Adding rooms, admins

In order to do anything useful you will want to add a room and admins to your SOGS installation
(unless upgrading: see below).

To interact with the SOGS database you want to run `python3 -msogs --help` from the session-pysogs
directory which will give you a description of the available commands to control your SOGS
installation.

See [SOGS Administration](administration.md) for details, but note that where that document
indicates using the `sogs` command you should instead use `python3 -msogs` from the `session-pysogs`
directory.

### Step 6: Check web viewer functionality

Navigating to your SOGS URL should display a web viewer of your open group, including any configured
rooms.  Navigating to the listed rooms will give you the full SOGS URL (and QR code) that is used to
have a Session client connect to the open group.

## Extras

### Upgrading

To upgrade simple stop your sogs service, `git pull` to update to the latest git repository code,
and start sogs again.  It's recommended that you also install regular OS updates.

### Upgrading from SOGS 0.1.x

To upgrade from a 0.1.x version of (Rust) SOGS you will need to do two things:

- Copy `database.db`, `x25519_private_key.pem`, `files`, and `rooms` from the old sogs data
  directory into the session-pysogs project directory.
- Manually convert your keys from the old openssl format, using:
```bash
python3 -msogs.key_convert -i x25519_private_key.pem -o key_x25519
```

The first time you start sogs after doing this it will see that it has no rooms but that
`database.db` exists and will perform a full import.  Note that you should leave the `files`
directory in place after this import: existing, imported uploads are left in their existing
locations until they expire.  The other old data files are not used after a successful import.

### Backing up

It is recommended that you make automatic, regular backups of your PySOGS data files.  In particular
you want to regularly back up `sogs.db` (which contains all the rooms and posts) and the `uploads`
directory (which contains uploaded files and room images).  You also want to make a one-time backup
of `key_x25519` (your SOGS private key needed to process SOGS requests).
