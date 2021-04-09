FROM docker.sunet.se/eduid/python3env

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

COPY . /opt/eduid/VCCS2
RUN (cd /opt/eduid/VCCS2; git describe; git log -n 1) > /revision.txt
RUN rm -rf /opt/eduid/VCCS2/.git
RUN /opt/eduid/bin/pip install -U pip wheel
RUN /opt/eduid/bin/pip install --index-url https://pypi.sunet.se -r /opt/eduid/VCCS2/requirements.txt
RUN /opt/eduid/bin/pip install /opt/eduid/VCCS2

COPY docker/start.sh /

EXPOSE "8000"
HEALTHCHECK --interval=27s CMD curl http://localhost:8000/status/healthy | grep -q STATUS_OK

CMD [ "/start.sh" ]
