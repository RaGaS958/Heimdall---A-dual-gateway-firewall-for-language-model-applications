# Heimdall frontend: build the site, then serve it with nginx, which also forwards /api to the middleware.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Runs as a non-root user and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
