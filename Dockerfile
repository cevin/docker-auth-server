FROM golang:1.17 as build

WORKDIR /opt/src

ADD . .

ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct \
    CGO_ENABLED=0

RUN go build -o auth main.go

FROM scratch

COPY --from=build /opt/src/auth /auth
COPY config.json /config.json

CMD ["/auth"]

