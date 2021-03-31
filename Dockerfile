FROM bitnami/owncloud:10-debian-10
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y git
RUN git clone -b tf-owncloud https://github.com/crystaluniverse/tf-owncloud.git
RUN cp -rf tf-owncloud/core /opt/bitnami/owncloud/
RUN cp -rf tf-owncloud/lib  /opt/bitnami/owncloud/
USER root
ENTRYPOINT [ "/opt/bitnami/scripts/owncloud/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/owncloud/run.sh" ]
