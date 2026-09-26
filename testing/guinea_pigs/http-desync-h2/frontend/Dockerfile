FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "h2>=4.0"
COPY proxy.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 80
# h2c edge (h2 lib): copies content-length verbatim into the h1 rewrite; blocks /admin.
CMD ["python", "proxy.py"]
