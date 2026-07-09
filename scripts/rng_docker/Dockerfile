# RNG statistical suites: dieharder + NIST SP 800-22 STS 2.1.2
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        dieharder \
        build-essential \
        wget \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget -q -O sts-2_1_2.zip \
      https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip \
    && unzip -q sts-2_1_2.zip \
    && make -C /opt/sts-2.1.2/sts-2.1.2 -j"$(nproc)" \
    && ln -sf /opt/sts-2.1.2/sts-2.1.2/assess /usr/local/bin/assess \
    && chmod +x /opt/sts-2.1.2/sts-2.1.2/experiments/create-dir-script \
    && (cd /opt/sts-2.1.2/sts-2.1.2/experiments && ./create-dir-script || true) \
    && test -x /usr/local/bin/assess \
    && which dieharder

COPY nist_assess.sh /usr/local/bin/nist_assess
RUN chmod +x /usr/local/bin/nist_assess

WORKDIR /data
