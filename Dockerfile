# Builds the Tamperlens MCP server and runs it over stdio. Glama (and any other
# MCP host) starts this image and speaks JSON-RPC to it on stdin/stdout; the
# server needs nothing but Node and answers tools/list without any credential.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY --from=build /app/dist ./dist
# stdio MCP server: no port, no network needed to introspect.
ENTRYPOINT ["node", "dist/index.js"]
