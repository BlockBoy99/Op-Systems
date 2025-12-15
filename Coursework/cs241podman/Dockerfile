FROM alpine:3.22.2
RUN apk add --no-cache build-base bash libpcap-dev python3 scapy wget curl
RUN apk add --no-cache hping3 --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing
ENTRYPOINT ["/bin/bash"]
