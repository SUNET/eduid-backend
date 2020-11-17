FROM docker.sunet.se/eduid/python3env

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

VOLUME ["/opt/eduid", "/opt/eduid/run", "/opt/eduid/src", "/var/log"]

ADD . /opt/eduid/eduid-queue

RUN /opt/eduid/eduid-queue/docker/setup.sh
RUN /opt/eduid/eduid-queue/docker/build.sh

RUN (cd /opt/eduid/eduid-queue; git describe; git log -n 1) > /revision.txt
RUN rm -rf /opt/eduid/eduid-queue/.git

WORKDIR "/opt/eduid/eduid-queue"
