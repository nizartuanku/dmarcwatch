# DmarcWatch — minimal production image.
# Build:  docker build -t dmarcwatch .
# Run:    docker run -d -p 127.0.0.1:8429:8429 -v dmarcwatch-data:/data dmarcwatch

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/dmarcwatch ./cmd/dmarcwatch

FROM debian:bookworm-slim
# /data is created and chowned here so a named volume inherits the app user's
# ownership. Without this the volume defaults to root:root and the unprivileged
# process cannot create its database.
RUN useradd -r -u 10001 dmarcwatch \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /data \
 && chown dmarcwatch:dmarcwatch /data
COPY --from=build /out/dmarcwatch /usr/local/bin/dmarcwatch
USER dmarcwatch
VOLUME /data
EXPOSE 8429
ENTRYPOINT ["dmarcwatch", "-listen", "0.0.0.0:8429", "-db", "/data/dmarcwatch.db", "-license", "/data/dmarcwatch-license.key"]
