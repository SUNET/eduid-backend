FROM docker.sunet.se/eduid/python3env

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

VOLUME ["/opt/eduid/eduid-lookup-mobile/etc", "/var/log/eduid", "/opt/eduid/src"]

COPY . /src/eduid-lookup-mobile
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
