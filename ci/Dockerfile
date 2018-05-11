FROM debian:latest

ENV DEBIAN_FRONTEND noninteractive


# auto validate license
RUN apt-get update && \
    apt install -y locales curl software-properties-common gnupg && \
    apt install -y rsync python && \
    echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu trusty main" | tee -a /etc/apt/sources.list && \
    echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu trusty main" | tee -a /etc/apt/sources.list && \
    echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EEA14886 && apt-get update && apt-get install -y curl dnsutils oracle-java8-installer ca-certificates && \
    mkdir -p /opt/code && \
    locale-gen en_US.UTF-8 en_us && dpkg-reconfigure locales && dpkg-reconfigure locales && locale-gen C.UTF-8 && /usr/sbin/update-locale LANG=C.UTF-8

ENV JAVA_HOME /usr/lib/jvm/java-8-oracle
ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

RUN groupadd --gid 1000 node \
    && useradd --uid 1000 --gid node --shell /bin/bash --create-home node

# gpg keys listed at https://github.com/nodejs/node#release-team
RUN wget https://github.com/Thrustjs/thrust/releases/download/0.4.1-1/thrust_0.4.1-1_all.deb \
    && dpkg -i thrust_0.4.1-1_all.deb