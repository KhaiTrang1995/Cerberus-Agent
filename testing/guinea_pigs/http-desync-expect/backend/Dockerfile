FROM python:3.12-slim
WORKDIR /app
COPY app.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
# Raw-socket origin (stdlib only): liberal Transfer-Encoding + Expect CL.0.
CMD ["python", "app.py"]
