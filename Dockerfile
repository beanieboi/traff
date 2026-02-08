FROM alpine:3.23

RUN apk add --no-cache \
    zig \
    libpcap-dev \
    musl-dev \
    mariadb-dev \
    postgresql-dev

WORKDIR /src
COPY . .

RUN zig build -Dmysql=true -Dpsql=true -Dtarget=native-native-musl

CMD ["/src/zig-out/bin/traff", "-c", "/etc/traff.conf"]
