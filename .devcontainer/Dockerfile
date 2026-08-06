# Remember to update the devcontainer image version to match the version used in production 
# See here: https://github.com/devcontainers/images/tree/main/src/base-debian
FROM mcr.microsoft.com/devcontainers/base:trixie

ARG NONROOT_USER=vscode
ENV NONROOT_USER=${NONROOT_USER}

# Copy the CI-owned shared package list into the image so the build can source
# the same repo system dependencies that workflows install on GitHub runners.
COPY --chmod=0644 .github/repo-system-packages.sh /usr/local/share/repo-system-packages.sh

# Keep the Dockerfile phases aligned with `make bootstrap` while using a single image layer.
RUN set -eux; \
    bootstrap_python_packages='python3 python3-dev python3-pip python3-venv'; \
    # Reuse the CI-owned repo package list so the devcontainer and workflows
    # install the same shared system dependencies from one source of truth.
    . /usr/local/share/repo-system-packages.sh; \
    # Keep swig available for PKCS#11-related native builds. It was originally
    # added alongside pyXMLSecurity[PKCS11], and retaining it avoids regressions
    # if that dependency path falls back to a source build again.
    native_build_tool_packages='swig'; \
    container_tool_packages='docker.io'; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        $bootstrap_python_packages \
        $repo_system_packages \
        $native_build_tool_packages; \
    python3 -m pip install --break-system-packages --no-cache-dir uv; \
    apt-get install -y $container_tool_packages; \
    rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 .devcontainer/docker-init.sh /usr/local/share/docker-init.sh

# VS Code overrides ENTRYPOINT and CMD when executing `docker run` by default.
# This devcontainer uses Docker-outside-of-Docker: it mounts the host Docker
# socket instead of starting a daemon inside the container. We still want the
# editor and shell to run as ${NONROOT_USER}, but the mounted socket's group ID
# comes from the host and can vary by machine. Startup therefore stays as root
# long enough for docker-init.sh to align socket permissions, then the entrypoint
# re-execs the requested command as ${NONROOT_USER}.
# Setting the ENTRYPOINT to docker-init.sh will configure non-root access to
# the mounted Docker socket if "overrideCommand": false is set in devcontainer.json.
# The script will also execute CMD if you need to alter startup behaviors.
ENTRYPOINT [ "/usr/local/share/docker-init.sh" ]
CMD [ "sleep", "infinity" ]