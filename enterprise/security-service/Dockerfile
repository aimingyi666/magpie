FROM node:26-alpine

ARG SECURITY_UID=10004
ARG SECURITY_GID=10004

WORKDIR /app
COPY package.json ./
COPY src ./src

RUN addgroup -S -g "${SECURITY_GID}" magpie \
    && adduser -S -D -H -u "${SECURITY_UID}" -G magpie magpie \
    && mkdir -p /data \
    && chown -R magpie:magpie /app /data

USER magpie
EXPOSE 3450
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3450/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
