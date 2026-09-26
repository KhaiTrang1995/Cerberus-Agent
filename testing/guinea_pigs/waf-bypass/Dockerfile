# nginx with a baked self-signed cert, used for BOTH the WAF edge and the origin.
# The cert is generated at build time so the containers need no runtime network.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/certs \
 && openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
      -days 3650 -subj "/CN=waf-lab" 2>/dev/null
