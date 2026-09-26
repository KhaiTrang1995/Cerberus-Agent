FROM python:3.12-slim
WORKDIR /app
COPY app.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
# Raw-socket origin (stdlib only): CL.0 (ignores body on server-generated endpoints).
CMD ["python", "app.py"]
