FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.6 asyncpg==0.30.0 redis==5.2.1

COPY app.py /app/app.py
EXPOSE 8081
CMD ["python3", "/app/app.py"]
