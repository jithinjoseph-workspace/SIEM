FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./

# Clean install
RUN npm install --legacy-peer-deps

COPY . .

# Fix permission issue
RUN chmod -R 755 node_modules/.bin

# Build the Angular SPA
RUN node ./node_modules/@angular/cli/bin/ng build

# ── Production stage: serve the built SPA via nginx ──
FROM nginx:alpine

COPY --from=build /app/dist/ndr-ui/browser /usr/share/nginx/html
RUN chmod -R 755 /usr/share/nginx/html

# Minimal nginx config: serve the Angular SPA on port 80.
# All /api and /ws proxying is handled by the outer ndr-nginx container.
# Only serve static files here — no upstream needed.
RUN printf 'events { worker_connections 1024; }\n\
http {\n\
  include       /etc/nginx/mime.types;\n\
  default_type  application/octet-stream;\n\
  sendfile      on;\n\
\n\
  server {\n\
    listen 80;\n\
    root  /usr/share/nginx/html;\n\
    index index.html;\n\
\n\
    # Angular SPA — all routes fall back to index.html\n\
    location / {\n\
      try_files $uri $uri/ /index.html;\n\
    }\n\
  }\n\
}\n' > /etc/nginx/nginx.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
