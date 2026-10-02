# RedAmon fix-regression guinea pig. Pure stdlib + a baked self-signed cert.
FROM python:3.11-alpine

RUN apk add --no-cache openssl && \
    mkdir -p /app/tls && \
    openssl req -x509 -newkey rsa:2048 -keyout /app/tls/key.pem -out /app/tls/cert.pem \
        -days 3650 -nodes -subj "/CN=fixreg.lab" >/dev/null 2>&1

WORKDIR /app
COPY server.py /app/server.py
ENV PYTHONUNBUFFERED=1
EXPOSE 22 80 443 3306 6379 8443
CMD ["python3", "/app/server.py"]
