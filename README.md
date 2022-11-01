# PySOGS (Session Community Server)

PySOGS is the reference implementation of a Session Community server (formerly known as a Session
Open Group). PySOGS is used to run the official Session Communities, and is the officially supported
Session Community server.  New features added to Session Communities are developed here in lockstep
with the support added to the Session clients.

## Installation

For most servers we provide and recommend using the .deb installation method on a VPS running Ubuntu
20.04 (or newer), or Debian 11 (or newer).

Alternatively advanced users and developers interested in running or working on the latest
development code may prefer to run directly from the repository using uwsgi.

While both methods are supported modes of operation, the latter requires more configuration and
maintenance and requires some experience with running Python code and web applications.

[Debian/Ubuntu Package Install](install-debs.md)

[Manual Installation](install-uwsgi.md)

## Administration

For how to administer a running PySOGS see [SOGS Administration](administration.md).

## License

Copyright (c) 2021-2022 The Oxen Project

PySOGS is licensed under the [GNU General Public License (GPL) v3](LICENSE.txt), or (at your option)
any later version.
