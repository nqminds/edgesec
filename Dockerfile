FROM ubuntu:22.04
# we recommend ubuntu 22.04 for cmake 3.22+ support

ENV TZ=Europe
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update && apt install -y tzdata wget cmake git ca-certificates doxygen texinfo graphviz build-essential automake autopoint gettext autoconf libtool-bin pkg-config libjson-c-dev flex bison
RUN mkdir /opt/EDGESec

WORKDIR /opt

RUN wget https://github.com/richfelker/musl-cross-make/archive/master.tar.gz
RUN tar xzf master.tar.gz
WORKDIR /opt/musl-cross-make-master
COPY ./config.mak ./
RUN make
RUN make install
