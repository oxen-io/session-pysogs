# Debian/Ubuntu Package Installation

We package and update .deb packages for PySOGS for Ubuntu 20.04 and newer, and for Debian 10 and
newer.  If starting out with a new server we recommend either the latest Debian stable release
(currently Debian 11) or Ubuntu LTS release (currently 20.04).

Our apt repository includes various dependencies and libraries, but most important are these two
packages (only one of which may be installed at a time):

### sogs-standalone

This is the package most simple SOGS setup will want to install.  It installs a SOGS that listens on
a public IP/port for HTTP connections.  It does not support HTTPS connections (but since all
messages to/from SOGS are separately encrypted, HTTPS is not particularly recommended anyway).

### sogs-proxied

This package provides a more advanced SOGS configuration where SOGS itself will listen on an
internal port and expects to have requests proxied to it from an ngnix or apache2 front-end server
that listens on the public IP/port.  The package will install basic site configuration files for
either nginx or apache2, but extra configuration may be necessary.

This package is required if you want your SOGS to be reached over HTTPS: the HTTPS handling is
configured on the front-end server (i.e. in nginx or apache) using a tool such as `certbot`.  (This
package does not auto-configure such HTTPS certificates, but there are many online help pages on
setting up such HTTPS support for a front-end web server).

If you don't know what any of this means then stick with the `sogs-standalone` package.

## Installation

To install the debian packages you need to set up the Oxen apt repository using the following
commands (this only needs to be done once on the server, and you may have already done it if you are
already using other Oxen deb packages on the server):

```bash
# Install the Oxen apt repository public signing key:
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
# Add the Oxen apt repository to your package configuration:
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
# Update package lists:
sudo apt update
```

and then install **ONE** of the sogs packages:
```bash
sudo apt install sogs-standalone
```
or
```bash
sudo apt install sogs-proxied
```

This will install and activate the sogs service.

During installation you will be prompted to enter the public SOGS URL.  While you may use your bare
IP address here, we recommend instead using a DNS hostname so that your SOGS site can be moved to a
different server or ISP in the future: hostnames are easily updated to point to a new location, IP
addresses are not.

## Configuring sogs

SOGS has a few options for configuration; the default packages install a configuration file in
/etc/sogs/sogs.ini that may be edited to tweak how your SOGS operates.  Comments are provided in the
file to describe each option.

After changing settings in `sogs.ini` you need to restart sogs for the changes to take effect using:

```bash
sudo systemctl restart sogs.service
```
(which works for both the standalone or the proxied version).

The default sogs installation has no rooms or admins; in order to start using it you must use the
command-line tools to set up initial rooms/users.  See [SOGS Administration](administration.md) for
details.

## Upgrading

As we develop SOGS we routinely push package updates to the deb repository.  To upgrade to the
latest version simply run:

```bash
sudo apt update
sudo apt upgrade
```

Note that this installs all available system package updates (not just SOGS-related packages), which
is generally a good thing as there may be security updates for the OS that should be installed as
well.

## Upgrading from SOGS 0.1.x

The deb packages automatically upgrading from the previous versions of sogs (which used the package
name `session-open-group-server`).  The procedure is exactly the same as above; during installation
the existing private key will be converted to the format PySOGS expects, and the first time SOGS
(i.e.  the new PySOGS code) starts up it will notice that it has an empty database, will detect the
old SOGS databases, and will import all data from them.  (The old database files are preserved in
case anything goes wrong).

## Backing up

It is recommended that you make automatic, regular backups of your PySOGS data files.  In particular
you want to regularly back up everything in /var/lib/session-open-group-server and the main sogs
configuration file, /etc/sogs/sogs.ini.
