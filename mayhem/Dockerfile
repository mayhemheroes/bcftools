FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbz2-dev liblzma-dev libcurl3-dev libz-dev git build-essential clang

RUN git clone --recursive https://github.com/samtools/htslib.git

COPY . /repo
WORKDIR /repo
ENV DESTDIR=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_vcmp_set_ref.cpp -fsanitize=fuzzer,address -I /repo/ -I /htslib/ vcmp.o /htslib/libhts.a -lpthread -lz -lm -lbz2 -llzma -lcurl -lz -lpthread -o /fuzz

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libz-dev libbz2-dev liblzma-dev libcurl3-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_vcmp_set_ref
