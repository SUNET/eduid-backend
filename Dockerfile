FROM docker.sunet.se/eduid/python3env

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

VOLUME ["/opt/eduid/etc", "/opt/eduid/run", "/opt/eduid/src", "/var/log"]

ADD . /opt/eduid/eduid-webapp

RUN /opt/eduid/eduid-webapp/docker/setup.sh

# revision.txt is dynamically updated by the CI for every build,
# to ensure build.sh is executed every time
ADD docker/revision.txt /revision.txt

RUN /opt/eduid/eduid-webapp/docker/build.sh

