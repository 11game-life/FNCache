FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY oncache-agent /oncache-agent
COPY tc_prog_kern.o /opt/oncache/bpf/tc_prog_kern.o

ENTRYPOINT ["/oncache-agent"]
