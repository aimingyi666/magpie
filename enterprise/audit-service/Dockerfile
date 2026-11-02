FROM node:26-alpine

ARG AUDIT_UID=10003
ARG AUDIT_GID=10003

WORKDIR /app
COPY package.json ./
COPY src ./src

RUN addgroup -S -g "${AUDIT_GID}" magpie \
    && adduser -S -D -H -u "${AUDIT_UID}" -G magpie magpie \
    && mkdir -p /data \
    && chown -R magpie:magpie /app /data

USER magpie
EXPOSE 3449
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3449/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
