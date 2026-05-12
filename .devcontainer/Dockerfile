FROM mcr.microsoft.com/devcontainers/base:trixie

ARG NONROOT_USER=vscode

# enabling non-root access to docker as outlined in docker-from-docker
RUN apt-get update && apt install -y curl python-is-python3 python3 python3-venv swig xmlsec1 docker.io ghostscript libcairo2-dev \
    && curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
    && cat <<EOF >/usr/local/share/docker-init.sh
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

# VS Code overrides ENTRYPOINT and CMD when executing `docker run` by default.
# Setting the ENTRYPOINT to docker-init.sh will configure non-root access to
# the Docker socket if "overrideCommand": false is set in devcontainer.json.
# The script will also execute CMD if you need to alter startup behaviors.
ENTRYPOINT [ "/usr/local/share/docker-init.sh" ]
CMD [ "sleep", "infinity" ]