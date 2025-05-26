FROM ubuntu:22.04

# 1) 필수 패키지
RUN apt-get update && apt-get install -y \
    clang libbpf-dev libelf-dev build-essential \
    linux-headers-$(uname -r) python3-pip curl

# 2) 소스 복사 & 빌드
WORKDIR /opt/crosslayer-guard
COPY . .

RUN make && make install

# 3) entrypoint
COPY docker/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
