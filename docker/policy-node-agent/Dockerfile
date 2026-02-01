FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        init-system-helpers \
        libtss2-esys-3.0.2-0t64 \
        libtss2-mu-4.0.1-0t64 \
        libtss2-tctildr0t64 \
    && rm -rf /var/lib/apt/lists/*

ARG DEB=policy-node-agent_0.1.0_amd64.deb

COPY ${DEB} /tmp/pkg.deb
# The package recommends policy-engine but does not require it on the same host
# when deployed in containers; --ignore-depends satisfies dpkg's bookkeeping.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && dpkg --ignore-depends=policy-engine -i /tmp/pkg.deb \
    && rm /tmp/pkg.deb /usr/sbin/policy-rc.d

# Config and identity files must be provided via bind mounts at runtime.
RUN mkdir -p /etc/policy-node-agent

ENTRYPOINT ["/usr/bin/policy-node-agent", "--config", "/etc/policy-node-agent/config.toml"]
