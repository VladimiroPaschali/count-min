FROM ubuntu:latest
#FROM rust:latest

WORKDIR /usr/src/app
COPY . .

#RUN apt-get update && \
#       apt-get install -y clang llvm libelf-dev libpcap-dev build-essential \
#       linux-perf bpftool

RUN apt-get update && \
    apt-get install -y clang llvm libelf-dev libpcap-dev \
                         build-essential linux-tools-$(uname -r) \
                        linux-headers-$(uname -r) linux-tools-common \
                        linux-tools-generic curl libssl-dev
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
#ENV PATH="$HOME/.cargo/bin:$PATH"
ENV PATH="/root/.cargo/bin:${PATH}"
#RUN source $HOME/.cargo/env
RUN rustup install stable
RUN rustup toolchain install nightly --component rust-src
RUN cargo install bpf-linker
RUN cargo install cargo-generate
RUN cargo xtask build-ebpf
#RUN RUST_LOG=info cargo xtask run