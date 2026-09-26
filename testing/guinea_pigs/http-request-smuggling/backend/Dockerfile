FROM python:3.12-slim

WORKDIR /app
COPY app.py .

ENV PYTHONUNBUFFERED=1
EXPOSE 5000
# Raw-socket origin (stdlib only): honors Transfer-Encoding, keep-alive.
CMD ["python", "app.py"]
