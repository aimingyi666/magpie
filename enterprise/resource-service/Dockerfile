FROM node:26-alpine

ARG RESOURCE_UID=10001
ARG RESOURCE_GID=10001

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY docker-entrypoint.sh /usr/local/bin/resource-entrypoint

RUN addgroup -S -g "${RESOURCE_GID}" magpie \
    && adduser -S -D -H -u "${RESOURCE_UID}" -G magpie magpie \
    && chmod 0555 /usr/local/bin/resource-entrypoint \
    && mkdir -p /data /content \
    && chown -R magpie:magpie /app /data /content

USER magpie
EXPOSE 3447
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3447/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/resource-entrypoint"]
CMD ["node", "src/server.js"]
