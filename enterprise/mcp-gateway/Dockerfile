FROM node:26-alpine

ARG MCP_UID=10002
ARG MCP_GID=10002

WORKDIR /app
COPY package.json ./
COPY src ./src

RUN addgroup -S -g "${MCP_GID}" magpie \
    && adduser -S -D -H -u "${MCP_UID}" -G magpie magpie \
    && mkdir -p /data \
    && chown -R magpie:magpie /app /data

USER magpie
EXPOSE 3448
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3448/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
