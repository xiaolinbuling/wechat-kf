FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.cloud.tencent.com/pypi/simple

COPY app.py .

EXPOSE 80
CMD ["sh", "-c", "gunicorn -w 2 -k gthread --threads 4 -b 0.0.0.0:${PORT:-80} app:app"]
