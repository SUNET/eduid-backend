# Remember to update the devcontainer image version to match the version used in production 
# See here: https://github.com/devcontainers/images/tree/main/src/base-debian
FROM mcr.microsoft.com/devcontainers/base:trixie

ARG NONROOT_USER=vscode

# Minimum system packages required for `make bootstrap`.
RUN apt-get update \
    && apt install -y python3 python3-dev python3-packaging python3-pip python3-venv libcairo2-dev \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip install --break-system-packages --no-cache-dir uv

# Additional tools used by the devcontainer beyond the bootstrap flow.
RUN apt-get update \
    && apt install -y swig xmlsec1 docker.io ghostscript \
    && rm -rf /var/lib/apt/lists/*

# Enable non-root access to Docker as outlined in Docker-in-Docker.
RUN cat <<EOF >/usr/local/share/docker-init.sh
#!/bin/sh
sudoIf() { if [ "\$(id -u)" -ne 0 ]; then sudo "\$@"; else "\$@"; fi; }
if [ -S /var/run/docker.sock ]; then
    SOCKET_GID=\$(stat -c '%g' /var/run/docker.sock)
    if [ "\${SOCKET_GID}" != '0' ]; then
        if ! getent group "\${SOCKET_GID}" >/dev/null; then
            sudoIf groupadd --gid "\${SOCKET_GID}" docker-host
        fi
        if ! id "${NONROOT_USER}" | grep -Eq "groups=.*(=|,)\${SOCKET_GID}\\("; then
            sudoIf usermod -aG "\${SOCKET_GID}" "${NONROOT_USER}"
        fi
    fi
fi
exec "\$@"
EOF

RUN chmod +x /usr/local/share/docker-init.sh

USER ${NONROOT_USER}

# VS Code overrides ENTRYPOINT and CMD when executing `docker run` by default.
# Setting the ENTRYPOINT to docker-init.sh will configure non-root access to
# the Docker socket if "overrideCommand": false is set in devcontainer.json.
# The script will also execute CMD if you need to alter startup behaviors.
ENTRYPOINT [ "/usr/local/share/docker-init.sh" ]
CMD [ "sleep", "infinity" ]