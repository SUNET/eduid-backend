FROM mcr.microsoft.com/devcontainers/python:3-3.13-trixie

ARG NONROOT_USER=vscode

# enabling non-root access to docker as outlined in docker-from-docker
RUN apt-get update && apt install -y swig xmlsec1 python3-venv docker.io ghostscript libcairo2-dev \
    && echo -e "#!/bin/sh\n\
    sudoIf() { if [ \"\$(id -u)\" -ne 0 ]; then sudo \"\$@\"; else \"\$@\"; fi }\n\
    SOCKET_GID=\$(stat -c '%g' /var/run/docker.sock) \n\
    if [ \"${SOCKET_GID}\" != '0' ]; then\n\
        if [ \"\$(cat /etc/group | grep :\${SOCKET_GID}:)\" = '' ]; then\n\
            sudoIf groupadd --gid \${SOCKET_GID} docker-host\n\
        fi \n\
        if [ \"\$(id ${NONROOT_USER} | grep -E \"groups=.*(=|,)\${SOCKET_GID}\(\")\" = '' ]; then\n\
            sudoIf usermod -aG \${SOCKET_GID} ${NONROOT_USER}\n\
        fi\n\
    fi\n\
    exec \"\$@\"" > /usr/local/share/docker-init.sh \
    && chmod +x /usr/local/share/docker-init.sh

# VS Code overrides ENTRYPOINT and CMD when executing `docker run` by default.
# Setting the ENTRYPOINT to docker-init.sh will configure non-root access to
# the Docker socket if "overrideCommand": false is set in devcontainer.json.
# The script will also execute CMD if you need to alter startup behaviors.
ENTRYPOINT [ "/usr/local/share/docker-init.sh" ]
CMD [ "sleep", "infinity" ]