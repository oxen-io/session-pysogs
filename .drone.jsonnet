local cargo = 'cargo --color=always --verbose ';

// Regular build on a rust docker image:
local rust_pipeline(
    name,
    image='rust:1-bullseye',
    cargo_extra='--release',
    tests=true,
    deb=null,  // set to distro name to make a deb
    deb_revision_suffix='',
    jobs=6,
    arch='amd64'
      ) = {
    kind: 'pipeline',
    type: 'docker',
    name: name,
    platform: { arch: arch },
    steps: [{
               name: 'check',
               image: image,
               commands: [
                   'echo "Running on ${DRONE_STAGE_MACHINE}"',
                   cargo + 'check -j' + jobs + ' ' + cargo_extra,
               ],
           }, {
               name: 'build',
               image: image,
               commands: [cargo + 'build -j' + jobs + ' ' + cargo_extra],
           }] + (if tests then [{
                     name: 'tests',
                     image: image,
                     commands: [cargo + 'test -j' + jobs + ' ' + cargo_extra],
                 }] else [])
           + (if deb != null then [{
                  name: 'deb',
                  image: image,
                  commands: [
                      cargo + 'install -j' + jobs + ' cargo-deb',
                      'sed -i -Ee \'s/^revision = "([^~]*)(~.*)?"$/revision = "\\\\\\\\1' + deb_revision_suffix + '"/\' Cargo.toml',
                      cargo + 'deb',
                  ],
              }] else []),

};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';
local default_apt_deps = 'pkg-config libssl-dev';

// Build on a stock debian/ubuntu distro
local debian_pipeline(
    name,
    image,
    cargo_extra='--release',
    apt_deps=default_apt_deps,
    tests=true,
    deb=null,  // set to distro name to make a deb
    deb_revision_suffix='',
    jobs=6,
    arch='amd64'
      ) = {
    kind: 'pipeline',
    type: 'docker',
    name: name,
    platform: { arch: arch },
    steps: [{
        name: 'build',
        image: image,
        environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
        commands: [
                      'echo "Building on ${DRONE_STAGE_MACHINE}"',
                      'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                      apt_get_quiet + ' update',
                      apt_get_quiet + ' install -y eatmydata',
                      'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                      'eatmydata ' + apt_get_quiet + ' install -y cargo ' + apt_deps + (if deb != null then ' openssh-client' else ''),
                      cargo + 'build -j' + jobs + ' ' + cargo_extra,
                  ]
                  + (if tests then [cargo + 'test -j' + jobs + ' ' + cargo_extra] else [])
                  + (if deb != null then [
                         cargo + 'install -j' + jobs + ' cargo-deb',
                         'sed -i -Ee \'s/^revision = "([^~]*)(~.*)?"$/revision = "\\\\\\\\1' + deb_revision_suffix + '"/\' Cargo.toml',
                         cargo + 'deb',
                         './contrib/ci/drone-debs-upload.sh ' + deb,
                     ] else []),
    }],
};

[
    {
        name: 'lint check',
        kind: 'pipeline',
        type: 'docker',
        platform: { arch: 'amd64' },
        steps: [{
            name: 'format',
            image: 'rust:1-bullseye',
            commands: [
                'echo "Running on ${DRONE_STAGE_MACHINE}"',
                'rustup component add rustfmt',
                'cargo fmt -- --check --color=always',
            ],
        }],
    },
    rust_pipeline('Rust latest/Release (amd64)'),
    rust_pipeline('Rust latest/Debug (amd64)', cargo_extra=''),
    rust_pipeline('Rust latest/Release (ARM64)', arch='arm64'),

    // Various debian builds
    debian_pipeline('Debian sid (amd64)', 'debian:sid', deb='sid', deb_revision_suffix=''),
    debian_pipeline('Debian 11 (amd64)', 'debian:bullseye', deb='bullseye', deb_revision_suffix='~deb11'),
    debian_pipeline('Debian 11 (ARM64)', 'debian:bullseye', arch='arm64', deb='bullseye', deb_revision_suffix='~deb11'),
    debian_pipeline('Ubuntu 21.04 (amd64)', 'ubuntu:hirsute', deb='hirsute', deb_revision_suffix='~ubuntu2104'),
    debian_pipeline('Ubuntu 20.04 (amd64)', 'ubuntu:focal', deb='focal', deb_revision_suffix='~ubuntu2004'),
    debian_pipeline('Ubuntu 18.04 (amd64)', 'ubuntu:bionic', deb='bionic', deb_revision_suffix='~ubuntu1804'),
    rust_pipeline('Debian 10 (amd64)', 'rust:1-buster', deb='buster', deb_revision_suffix='~deb10'),

    // Macos build:
    {
        kind: 'pipeline',
        type: 'exec',
        name: 'MacOS/Release',
        platform: { os: 'darwin', arch: 'amd64' },
        steps: [
            {
                name: 'build',
                commands: [
                    'echo "Building on ${DRONE_STAGE_MACHINE}"',
                    'cargo build -j6 --release',
                    'cargo test -j6 --release',
                ],
            },
        ],
    },
]
