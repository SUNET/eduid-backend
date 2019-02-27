FROM docker.sunet.se/eduid/python3env

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

VOLUME ["/opt/eduid/eduid-msg/etc", "/var/log/eduid", "/opt/eduid/src"]

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y locales

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8

COPY . /src/eduid_msg
COPY docker/setup.sh /opt/eduid/setup.sh
RUN /opt/eduid/setup.sh

COPY docker/start.sh /start.sh

# Add Dockerfile to the container as documentation
COPY Dockerfile /Dockerfile

# revision.txt is dynamically updated by the CI for every build,
# to ensure build.sh is executed every time
COPY docker/revision.txt /revision.txt

COPY docker/build.sh /opt/eduid/build.sh
RUN /opt/eduid/build.sh

WORKDIR /

CMD ["bash", "/start.sh"]
