FROM debian:stable

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update && apt-get -y install \
    git \
    curl \
    python3-pip \
    python3.7-venv

COPY . /opt/eduid/VCCS2
RUN (cd /opt/eduid/VCCS2; git describe; git log -n 1) > /revision.txt
RUN rm -rf /opt/eduid/VCCS2/.git
RUN python3.7 -m venv /opt/eduid/env
RUN /opt/eduid/env/bin/pip install -U pip wheel
RUN /opt/eduid/env/bin/pip install --index-url https://pypi.sunet.se -r /opt/eduid/VCCS2/requirements.txt

COPY docker/start.sh /

EXPOSE "8000"
HEALTHCHECK --interval=27s CMD curl http://localhost:8000/status/healthy | grep -q STATUS_OK

CMD [ "/start.sh" ]
