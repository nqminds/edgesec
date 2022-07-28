FROM ubuntu:22.04
# we recommend ubuntu 22.04 for cmake 3.22+ support

ENV TZ=Europe
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir /opt/EDGESec

WORKDIR /opt

COPY ./debian/control ./debian/control


# install dependencies
RUN apt-get update && apt-get install devscripts equivs wget -y && \
    mk-build-deps --install --tool='apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes' ./debian/control

RUN wget https://github.com/richfelker/musl-cross-make/archive/master.tar.gz
RUN tar xzf master.tar.gz
WORKDIR /opt/musl-cross-make-master
COPY ./config.mak ./
RUN make
RUN make install
