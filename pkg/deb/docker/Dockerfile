FROM ubuntu:xenial

RUN echo 'Acquire::Retries "3";' > /etc/apt/apt.conf.d/80-retries && \
    sed -i 's|deb http://security|#deb http://security|g' /etc/apt/sources.list && \
    apt update && \
    apt install -y curl devscripts equivs tar gcc gzip pkg-config git

ADD entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]