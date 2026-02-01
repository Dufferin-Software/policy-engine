FROM debian:trixie-slim

# libbpf1 is the only runtime shared-library dependency of the engine binary.
# init-system-helpers provides deb-systemd-helper, called by the package postinst.
RUN apt-get update && apt-get install -y --no-install-recommends \
        adduser \
        libbpf1 \
        init-system-helpers \
    && rm -rf /var/lib/apt/lists/*

# Accept any of the four engine variants: policy-engine, policy-engine-ips,
# policy-engine-ipfix, policy-engine-ips-ipfix.
ARG DEB=policy-engine_0.1.0_amd64.deb

COPY ${DEB} /tmp/pkg.deb
# policy-rc.d prevents postinst from trying to start the service.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && dpkg -i /tmp/pkg.deb \
    && rm /tmp/pkg.deb /usr/sbin/policy-rc.d

# Config, state and log directories must be provided via bind mounts at runtime;
# they are intentionally not bundled in the image.
RUN mkdir -p /etc/policy-engine /var/lib/policy-engine /var/log/policy-engine

EXPOSE 8080

ENTRYPOINT ["/usr/bin/policy-engine"]
