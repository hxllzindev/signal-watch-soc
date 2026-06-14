FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=5000

WORKDIR /app
RUN apk upgrade --no-cache
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src

USER node
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:5000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
