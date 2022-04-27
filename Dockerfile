FROM --platform=linux/amd64 poddar009/maverics-debug:0.6.29
WORKDIR /etc/maverics
#USER root

#RUN apk add git
#RUN apk add strace

#USER maverics

RUN mkdir -p /etc/maverics/certs
RUN mkdir -p /etc/maverics/src
COPY --chown=maverics:maverics maverics.lic /etc/maverics/
COPY --chown=maverics:maverics maverics.yaml /etc/maverics/
COPY --chown=maverics:maverics fullchain.pem /etc/maverics/certs/
COPY --chown=maverics:maverics privkey.pem /etc/maverics/certs/
COPY --chown=maverics:maverics rootCA.pem /etc/maverics/certs/
COPY --chown=maverics:maverics strata.go /etc/maverics/
COPY --chown=maverics:maverics duoHandler.go /etc/maverics/
COPY --chown=maverics:maverics src/ /etc/maverics/src/