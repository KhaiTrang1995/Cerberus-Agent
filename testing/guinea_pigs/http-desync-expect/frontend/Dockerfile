FROM python:3.12-slim
WORKDIR /app
COPY proxy.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 80
# Raw-socket edge (stdlib only): strict canonical TE, CL fallback, blocks /admin.
CMD ["python", "proxy.py"]
