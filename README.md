## Manual Installation Instructions

#### Debs guide coming soon

### Step 1: Clone the PySOGS repo:

```git clone https://github.com/oxen-io/session-pysogs```

### Step 2: Grab dependencies:

``` apt install python3-{coloredlogs,uwsgidecorators,flask,cryptography,nacl,pil,protobuf,openssl,qrencode} uwsgi-plugin-python3 ```

You will also need python3-oxenmq , python3-oxenc and python3-pyonionreq

If you are on a debian based system these can be fetched from the deb.oxen.io repo, to add that repo execute the following

```sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
```

then 

```sudo apt install python3-oxenmq python3-oxenc python3-pyonionreq```

### Step 3: Adjust configuration

Navigate to cloned directory 

```cd session-pysogs```

Make copy of uwsgi.ini file

```cp contrib/uwsgi-sogs-direct.ini uwsgi-sogs.ini```

open in text editor of your choice

```nano uwsgi-sogs.ini```

Change relevant config settings including chdir, uid, gid other settings like http port can be altered if required

```chdir = LOCATION_OF_CLONED_DIRECTORY
uid = USER_RUNNING_SOGS
gid = USER_RUNNING_SOGS
http = :UNUSED_PORT
```
Make copy of sogs.ini file 

```cp sogs.ini.sample sogs.ini```

Open in text editor of your choice

```nano sogs.ini```

Uncomment and change the base URL to your base URL, this can be a domain name or a public ip address

For example
```base_url = http://232.111.62.186```
or 
```base_url = http://example.com```

### Step 4: Run SOGS

Once configured you can start PySOGS by running the following command while inside the root directory

```uwsgi uwsgi-sogs.ini```

You will want to setup a system service or run SOGS in a separate terminal window so that you can execute administrative commands while SOGS is running

### Step 5: Add room 

in the root directory run 

```python3 -msogs --add-room ROOMNAME```

replacing ROOMNAME with the desired name of the room, this should produce a result similar to below

```
Created room fishing:

fishing
=======
Name: fishing
Description: None
URL: http://5.161.62.186/fishing?public_key=e8303ae6992a8bfe0c6c1f1ebeb93f0f124d8548bc2dc687c94c81602692bc51
```

This URL can be used in Session to join the group

### Step 6: Add moderator to room

in the root directory run 

```python3 -msogs --rooms ROOMNAME --add-moderators SESSIONID```

for example 

```python3 -msogs --rooms fishing --add-moderators 05d871fc80ca007eed9b2f4df72853e2a2d5465a92fcb1889fb5c84aa2833b3b40```

### Step 6: Check web viewer functionality

Navigating to your BaseURL should display a web viewer of your open group 
