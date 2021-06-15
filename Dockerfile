FROM debian:latest

RUN apt-get update
RUN apt-get upgrade -y

RUN apt-get install curl -y
RUN apt-get install build-essential -y
RUN apt-get install libssl-dev -y
RUN apt-get install pkg-config -y

RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain stable -y

RUN mkdir session-open-group-server
ADD . /session-open-group-server
WORKDIR session-open-group-server

RUN ~/.cargo/bin/cargo build --release
RUN mkdir ./target/release/data
WORKDIR ./target/release/data

RUN openssl genpkey -algorithm x25519 -out x25519_private_key.pem
RUN openssl pkey -in x25519_private_key.pem -pubout -out x25519_public_key.pem

CMD ["../session-open-group-server"]