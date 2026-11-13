FROM node:22-bookworm-slim

WORKDIR /app
COPY package.json /app/package.json
RUN npm install --omit=dev --no-audit --no-fund

COPY server.mjs /app/server.mjs
EXPOSE 8082
CMD ["node", "/app/server.mjs"]
