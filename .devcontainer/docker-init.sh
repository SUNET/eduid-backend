#!/bin/sh

# This devcontainer talks to the host Docker daemon through a mounted
# /var/run/docker.sock instead of running a nested Docker daemon. To make that
# work without running the whole devcontainer as root, this helper creates or
# reuses a local group with the socket's GID, adds ${NONROOT_USER} to it, and
# then starts a fresh process so the new supplementary groups actually take
# effect.
sudoIf() { if [ "$(id -u)" -ne 0 ]; then sudo "$@"; else "$@"; fi; }
if [ -S /var/run/docker.sock ]; then
    SOCKET_GID=$(stat -c '%g' /var/run/docker.sock)
    if [ "${SOCKET_GID}" != '0' ]; then
        if ! getent group "${SOCKET_GID}" >/dev/null; then
            sudoIf groupadd --gid "${SOCKET_GID}" docker-host
        fi
        if ! id "${NONROOT_USER}" | grep -Eq "groups=.*(=|,)${SOCKET_GID}\\("; then
            sudoIf usermod -aG "${SOCKET_GID}" "${NONROOT_USER}"
        fi
    fi
fi

if [ "$(id -u)" -eq 0 ]; then
    exec sudo -E -H -u "${NONROOT_USER}" "$@"
fi

exec "$@"