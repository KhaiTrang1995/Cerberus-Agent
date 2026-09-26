FROM python:3.12-slim

WORKDIR /app
COPY proxy.py .

ENV PYTHONUNBUFFERED=1
EXPOSE 8080
# Raw-socket edge proxy (stdlib only): honors Content-Length, pools one keep-alive
# upstream to the backend, blocks /admin at the edge.
CMD ["python", "proxy.py"]
