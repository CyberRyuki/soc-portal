# Etapa 1: compilar la interfaz React (Vite)
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Etapa 2: servir con nginx (solo estáticos + proxy a soc-bridge)
FROM nginx:1.27-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY docker/nginx.conf /etc/nginx/conf.d/soc-web.conf
COPY --from=build /app/dist /usr/share/nginx/html/portal
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8088/portal/ >/dev/null || exit 1
