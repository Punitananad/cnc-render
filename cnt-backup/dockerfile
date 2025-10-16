FROM python:3.12-slim

# install system deps required to build psycopg2 and other wheels
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# CMD ["gunicorn","-w","4","app:app"]
CMD ["python","app.py"]
EXPOSE 5000