FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATASNIPER_HOST=0.0.0.0 \
    DATASNIPER_PORT=8787 \
    DATASNIPER_ALLOWED_HOSTS=localhost,127.0.0.1,datasniper

RUN useradd --create-home --uid 10001 datasniper
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data && chown -R datasniper:datasniper /app
USER datasniper
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health', timeout=3)"
CMD ["python", "run.py"]
