FROM node:26-alpine

WORKDIR /app
COPY package.json ./
COPY src ./src

RUN addgroup -S magpie && adduser -S -G magpie magpie \
    && mkdir -p /data && chown -R magpie:magpie /app /data

USER magpie
EXPOSE 3444
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3444/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
