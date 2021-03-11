FROM docker.sunet.se/eduid/python3env

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

VOLUME ["/opt/eduid/etc", "/opt/eduid/run", "/opt/eduid/src", "/var/log"]

COPY . /opt/eduid/eduid-scimapi
COPY ./docker/start.sh /start.sh

RUN (cd /opt/eduid/eduid-scimapi; git describe; git log -n 1) > /revision.txt
RUN rm -rf /opt/eduid/eduid-scimapi/.git

RUN /opt/eduid/eduid-scimapi/docker/setup.sh
RUN /opt/eduid/eduid-scimapi/docker/build.sh

WORKDIR /

EXPOSE 8000

HEALTHCHECK --interval=27s CMD curl http://localhost:8000/status/healthy | grep -q STATUS_OK

CMD ["bash", "/start.sh"]
