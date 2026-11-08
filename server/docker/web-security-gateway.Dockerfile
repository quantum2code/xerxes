FROM node:24-alpine AS build
WORKDIR /app
RUN npm install --global pnpm@10.7.1
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig*.json ./
COPY src ./src
RUN pnpm build && pnpm prune --prod

FROM node:24-alpine
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# Starts as capability-free root solely to bind/chmod the named-volume socket,
# then gateway-worker drops UID/GID to 1000 before handling any traffic.
CMD ["node", "dist/modules/web-security/network/gateway-worker.js"]
