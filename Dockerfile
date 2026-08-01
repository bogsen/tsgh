FROM golang:1.26.5-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tsgh ./cmd/tsgh

FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
    && addgroup -g 65532 nonroot \
    && adduser -D -H -u 65532 -G nonroot nonroot \
    && mkdir -p /var/lib/tsgh \
    && chown nonroot:nonroot /var/lib/tsgh
COPY --from=build /tsgh /tsgh
ENV TSGH_STATE_DIR=/var/lib/tsgh
VOLUME ["/var/lib/tsgh"]
USER 65532:65532
ENTRYPOINT ["/tsgh"]
