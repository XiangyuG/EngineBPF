FROM alexdecb/bcc:ubuntu2404

# Remove stale llvm repo from parent image. TODO: fix in parent image directly
RUN set -eux; \
    find /etc/apt/sources.list /etc/apt/sources.list.d -type f -maxdepth 1 2>/dev/null | xargs -r grep -n "apt.llvm.org" || true; \
    sed -i '/apt\.llvm\.org\/noble/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3-bpfcc iptables vim \
 && rm -rf /var/lib/apt/lists/*

# Download bpftool CLI (v7.6.0), extract, and install into /usr/bin
RUN curl -fsSL \
      https://github.com/libbpf/bpftool/releases/download/v7.6.0/bpftool-v7.6.0-amd64.tar.gz \
      -o /tmp/bpftool.tar.gz \
 && tar -xzf /tmp/bpftool.tar.gz -C /usr/bin \
 && rm -f /tmp/bpftool.tar.gz \
 && chmod +x /usr/bin/bpftool || true

WORKDIR /eebpf
COPY . /eebpf

CMD ["sleep", "infinity"]
