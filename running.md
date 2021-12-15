## Debian Package Install

`sogs-standalone` package runs sogs bare and it's the fastest and simplest setup (recommended).

`sogs-proxied` package runs sogs behind an nginx reverse proxy and allows for more advance flexible 
configuration, for experienced admins only.

To install the debian package for sogs (`sogs-standalone` or `sogs-proxied` ) do the following:

```
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install sogs-standalone
```

It will prompt for server name on install.

Add a room to the server:

```bash

sogs --add-room TOKEN --name "NAME"
```

Add yourself as an admin:


```bash
sogs --rooms TOKEN --add-moderators SESSIONID --admin
```


Visit your server via http in a browser to grab the room links via the web viewer.



## Manual Installation Instructions

### Step 0: Do Not Run PySOGS as root

Do not run pysogs as root.

### Step 1: Clone the PySOGS repo


```bash
git clone https://github.com/oxen-io/session-pysogs -b stable pysogs
cd pysogs
```

### Step 2: Grab dependencies

If you are on a debian based system these can be fetched from the `deb.oxen.io` repo, to add that
repo and install dependancies execute the following

```bash
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install python3-{oxenmq,oxenc,pyonionreq,coloredlogs,uwsgidecorators,flask,cryptography,nacl,pil,protobuf,openssl,qrencode,better-profanity} uwsgi-plugin-python3
```

### Step 3: Adjust configuration

Make copy of uwsgi.ini file

```bash
cp contrib/uwsgi-sogs-standalone.ini uwsgi-sogs.ini
```

Edit `uwsgi-sogs.ini`, change relevant config settings including chdir, uid, gid other settings like
http port can be altered if required

```ini
chdir = LOCATION_OF_CLONED_DIRECTORY
uid = USER_RUNNING_SOGS
gid = USER_RUNNING_SOGS
http = :UNUSED_PORT
```

Make copy of `sogs.ini` file and edit it

```bash
cp sogs.ini.sample sogs.ini
```

Uncomment and change the `base_url` setting to your SOGS URL; this can be a domain name or a public
ip address.  Using a domain name is recommended over a bare IP as it can later be moved to a new
host or new ISP, while while a bare IP cannot.

For example

```ini
base_url = http://sogs.example.com
```

### Step 4: Run SOGS

Once configured you can start PySOGS by running the following command while inside the git
repository base directory

```bash
uwsgi uwsgi-sogs.ini
```

### Step 5: Add room

To add a room run the following from the project directory:
```bash
python3 -msogs --add-room TOKEN --name "NAME"
```

replacing ROOMNAME with the desired name of the room, this should produce a result similar to below

```text
Created room fishing:

fishing
=======
Name: Fish Talk
Description: None
URL: http://sogs.example.net/fishing?public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

This URL can be used in Session to join the group

### Step 6: Add Admin to room

in the root directory run

```bash
python3 -msogs --rooms ROOMTOKEN --add-moderators SESSIONID --admin
```

Run `python3 -msogs --help` to see all available sogs command-line options.

### Step 7: Check web viewer functionality

Navigating to your SOGS URL should display a web viewer of your open
group


