FROM rust:latest


WORKDIR /usr/src/app
COPY . .

RUN cargo install bpf-linker
RUN cargo xtask build-ebpf
RUN RUST_LOG=info cargo xtask run