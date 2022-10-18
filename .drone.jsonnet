local docker_base = 'registry.oxen.rocks/lokinet-ci-';
local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local default_deps = [
  'python3',
  'python3-pytest',
  'python3-oxenmq',
  'python3-oxenc',
  'python3-pyonionreq',
  'python3-coloredlogs',
  'python3-uwsgidecorators',
  'python3-flask',
  'python3-cryptography',
  'python3-pycryptodome',
  'python3-nacl',
  'python3-pil',
  'python3-protobuf',
  'python3-openssl',
  'python3-qrencode',
  'python3-better-profanity',
  'python3-sqlalchemy',
  'python3-sqlalchemy-utils',
];

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local auto_distro = '$$(lsb_release -sc)';

local setup_commands(deps=default_deps, distro=auto_distro) = [
  'echo "Running on ${DRONE_STAGE_MACHINE}"',
  'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
  apt_get_quiet + ' update',
  apt_get_quiet + ' install -y eatmydata',
  'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y lsb-release',
  'cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d',
  'echo deb http://deb.oxen.io ' + distro + ' main >/etc/apt/sources.list.d/oxen.list',
  'eatmydata ' + apt_get_quiet + ' update',
  'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
  'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y ' + std.join(' ', deps),
];


// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      before_pytest=[],
                      pytest_opts='',
                      extra_cmds=[],
                      services=[],
                      allow_fail=false,
                      distro=auto_distro) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  trigger: { branch: { exclude: ['debian/*', 'ubuntu/*'] } },
  steps: [
    {
      name: '🐍 pytest',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      commands: setup_commands(deps=deps, distro=distro) + before_pytest + [
                  'pytest-3 -vv --color=yes ' + pytest_opts,
                ]
                + extra_cmds,
    },
  ],
  services: services,
};

local pg_deps = ['python3-psycopg2', 'postgresql-client'];
local pg_service(pg_tag='bullseye') = {
  name: 'pg',
  image: 'postgres:' + pg_tag,
  pull: 'always',
  environment: { POSTGRES_USER: 'ci', POSTGRES_PASSWORD: 'ci' },
};
local pg_wait = 'for i in $(seq 0 30); do if pg_isready -d ci -h pg -U ci -t 1; then break; elif [ "$i" = 30 ]; then echo "Timeout waiting for postgresql" >&2; exit 1; fi; sleep 1; done';

local debian_pg_pipeline(name, image, pg_tag='bullseye', distro=auto_distro) = debian_pipeline(
  name,
  image,
  deps=default_deps + pg_deps,
  services=[pg_service(pg_tag)],
  before_pytest=[pg_wait],
  pytest_opts='--pgsql "postgresql://ci:ci@pg/ci"',
  distro=distro
);

local upgrade_deps = default_deps + ['git', 'curl', 'sqlite3', 'python3-prettytable'];
local upgrade_test(name, from='v0.1.10', intermediates=[], pg=false, pg_convert=false) = {
  name: name,
  image: docker_base + 'debian-stable',
  pull: 'always',
  commands: setup_commands(deps=upgrade_deps
                                + (if pg || pg_convert then pg_deps else [])
                                + (if pg_convert then ['python3-pip'] else []))
            + [if pg || pg_convert then pg_wait]
            + [
              './contrib/upgrade-tests/' + from + '-upgrade.sh --delete-my-crap ' + std.join(' ', intermediates),
              './contrib/upgrade-tests/dump-db.py >upgraded-db.txt',
              'diff --color=always -sub contrib/upgrade-tests/' + from + '-expected.txt upgraded-db.txt',
            ] + (if pg_convert then [
                   'eatmydata pip3 install psycopg',
                   'PYTHONPATH=. ./contrib/pg-import.py sogs.db postgresql://ci:ci@pg/ci --drop-tables --commit',
                   'SOGS_PGSQL=postgresql://ci:ci@pg/ci ./contrib/upgrade-tests/dump-db.py >converted-db.txt',
                   'diff --color=always -sub contrib/upgrade-tests/' + from + '-expected.txt converted-db.txt',
                 ] else []),

  environment: if pg then { SOGS_PGSQL: 'postgresql://ci:ci@pg/ci' } else {},
};


[
  {
    name: 'Lint checks',
    kind: 'pipeline',
    type: 'docker',
    platform: { arch: 'amd64' },
    steps: [
      {
        name: 'Formatting',
        image: docker_base + 'debian-stable',
        pull: 'always',
        commands: [
          'echo "Running on ${DRONE_STAGE_MACHINE}"',
          apt_get_quiet + ' install -y black',
          'black --check --diff --color .',
        ],
      },
      {
        name: 'Flake8',
        image: docker_base + 'debian-stable',
        pull: 'always',
        commands: [
          'echo "Running on ${DRONE_STAGE_MACHINE}"',
          apt_get_quiet + ' install -y flake8',
          'flake8 .',
        ],
      },
    ],
  },

  debian_pipeline('Debian sid (amd64)', docker_base + 'debian-sid', distro='sid'),
  debian_pipeline('Debian stable (i386)', docker_base + 'debian-stable/i386'),
  debian_pipeline('Debian stable (amd64)', docker_base + 'debian-stable'),
  debian_pipeline('Ubuntu latest (amd64)', docker_base + 'ubuntu-rolling'),
  debian_pipeline('Ubuntu LTS (amd64)', docker_base + 'ubuntu-lts'),

  debian_pg_pipeline('PostgreSQL 15/sid', docker_base + 'debian-sid', pg_tag='15-bullseye', distro='sid'),
  debian_pg_pipeline('PostgreSQL 12/focal', docker_base + 'ubuntu-focal', pg_tag='12-bullseye'),

  // ARM builds (ARM64 and armhf)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64', distro='sid'),
  debian_pipeline('Debian stable (armhf)', docker_base + 'debian-stable/arm32v7', arch='arm64'),

  // Import tests:
  {
    name: 'Upgrades (sqlite)',
    kind: 'pipeline',
    type: 'docker',
    platform: { arch: 'amd64' },
    steps: [
      upgrade_test('sqlite3: 0.1.10→now'),
      upgrade_test('sqlite3: 0.1.10→0.2.0→now', intermediates=['43380beaa2']),
      upgrade_test('sqlite3: 0.2.0→now', from='v0.2.0'),
    ],
  },
  {
    name: 'Upgrades (pg)',
    kind: 'pipeline',
    type: 'docker',
    platform: { arch: 'amd64' },
    services: [pg_service()],
    steps: [
      upgrade_test('postgres: 0.1.10→now', pg=true),
      upgrade_test('postgres: 0.3.0→now', from='v0.3.0-pg', pg=true),
      upgrade_test('sqlite3-pg: 0.1.10→now→pg', pg_convert=true),
    ],
  },

  // Macos:
  {
    kind: 'pipeline',
    type: 'exec',
    name: 'MacOS',
    platform: { os: 'darwin', arch: 'amd64' },
    steps: [
      {
        name: '🐍 pytest',
        commands: [
          'echo "Running on ${DRONE_STAGE_MACHINE}"',
          'PYTHONPATH=. /opt/local/bin/python3 -mpytest -vv --color=yes',
        ],
      },
    ],
  },
]
