FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        init-system-helpers \
    && rm -rf /var/lib/apt/lists/*

ARG DEB=policy-controller_0.1.0_amd64.deb

COPY ${DEB} /tmp/pkg.deb
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && dpkg -i /tmp/pkg.deb \
    && rm /tmp/pkg.deb /usr/sbin/policy-rc.d

# Config and database must be provided via bind mounts at runtime.
RUN mkdir -p /etc/policy-controller /var/lib/policy-controller

# Operator API (HTTP/GraphQL), Enrollment gRPC, Node Management gRPC
EXPOSE 8443 7776 7777

ENTRYPOINT ["/usr/bin/policy-controller", "--config", "/etc/policy-controller/config.toml"]
