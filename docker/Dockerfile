ARG IMAGE_GOLANG=1.25.4
ARG IMAGE_ALPINE=3.22

FROM golang:${IMAGE_GOLANG}-alpine${IMAGE_ALPINE} AS build

WORKDIR /app

ADD . .

ARG GIT_COMMIT
ARG VERSION

ENV GO111MODULE=on

# RUN apk add --no-cache git

RUN go build \
    -o build/package/usr/local/sbin/ssl-pinning \
    -ldflags "-w -s \
    -X ssl-pinning/internal/version.version=${VERSION} \
    -X ssl-pinning/internal/version.gitCommit=${GIT_COMMIT} \
    " ssl-pinning

FROM alpine:${IMAGE_ALPINE}

COPY --from=build /app/build/package /

ENTRYPOINT ["/usr/local/sbin/ssl-pinning"]
