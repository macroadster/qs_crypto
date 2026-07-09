# TestU01 BigCrush environment for QS-Crypto SpinPrng streams
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        wget \
        ca-certificates \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget -q -O TestU01.zip \
      https://github.com/umontreal-simul/TestU01-2009/archive/refs/heads/master.zip \
    && unzip -q TestU01.zip \
    && cd TestU01-2009-master \
    && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && cd / && rm -rf /tmp/TestU01.zip /tmp/TestU01-2009-master

WORKDIR /opt/qs
COPY bigcrush_wrapper.c bigcrush_stream.c /opt/qs/
RUN gcc -O2 -o /usr/local/bin/bigcrush_wrapper /opt/qs/bigcrush_wrapper.c \
        -I/usr/local/include -L/usr/local/lib \
        -ltestu01 -lprobdist -lmylib -lm \
    && gcc -O2 -o /usr/local/bin/bigcrush_stream /opt/qs/bigcrush_stream.c \
        -I/usr/local/include -L/usr/local/lib \
        -ltestu01 -lprobdist -lmylib -lm

WORKDIR /data
# Default: stream mode (stdin). File mode: docker run ... bigcrush_wrapper /data/file.bin
ENTRYPOINT ["bigcrush_stream"]
