# RedAmon circuit-breaker guinea pig. Pure stdlib, no dependencies.
FROM python:3.11-alpine

WORKDIR /app
COPY server.py /app/server.py

ENV PYTHONUNBUFFERED=1

EXPOSE 80 443
CMD ["python3", "/app/server.py"]
