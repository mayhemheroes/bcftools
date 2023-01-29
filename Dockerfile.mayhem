FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbz2-dev liblzma-dev libcurl3-dev libz-dev git build-essential

RUN git clone --recursive https://github.com/samtools/htslib.git

COPY . /repo
WORKDIR /repo
ENV DESTDIR=/install
RUN make -j8
RUN make install

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcurl3-dev
COPY --from=builder /install /install
