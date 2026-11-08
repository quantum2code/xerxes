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
USER 1000:1000
# The controller creates a uid=1000 tmpfs volume; this process never needs root or setuid capabilities.
CMD ["node", "dist/engines/engine2/zap/gateway-worker.js"]
