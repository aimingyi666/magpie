# syntax=docker/dockerfile:1

# Build the matching Magpie binary from this fork. The adapter must invoke the
# same machine protocol version that owns the mounted gateway data volume.
FROM golang:1.26-alpine AS magpie-build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -tags nogui -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/magpie .

FROM node:26-alpine

WORKDIR /app
COPY enterprise/gateway-control/package.json ./
COPY enterprise/gateway-control/src ./src
COPY --from=magpie-build /out/magpie /usr/local/bin/magpie

# Use the same UID/GID as magpie's server image so the shared named volume is
# writable without widening permissions.
RUN addgroup -S -g 65532 magpie-control \
    && adduser -S -D -H -u 65532 -G magpie-control magpie-control \
    && mkdir -p /config \
    && chown -R magpie-control:magpie-control /app /config

USER magpie-control

ENV HOME=/config \
    XDG_CONFIG_HOME=/config \
    GATEWAY_CONTROL_BIND=0.0.0.0 \
    GATEWAY_CONTROL_PORT=3446 \
    GATEWAY_CONTROL_MAGPIE=/usr/local/bin/magpie \
    GATEWAY_CONTROL_CONFIG_HOME=/config

EXPOSE 3446

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3446/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
