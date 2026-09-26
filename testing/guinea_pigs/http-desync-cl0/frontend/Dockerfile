FROM python:3.12-slim
WORKDIR /app
COPY proxy.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 80
# Raw-socket streaming edge (stdlib only): pools one keep-alive upstream, blocks /admin.
CMD ["python", "proxy.py"]
