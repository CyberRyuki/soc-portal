# Chromium del sistema (Debian) + Playwright solo como controlador: no se descarga ningún navegador al construir.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends chromium fonts-dejavu-core fonts-liberation \
      fonts-noto-color-emoji ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10002 -m shots
WORKDIR /app
COPY requirements.txt .
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 CHROME_PATH=/usr/bin/chromium HOME=/tmp
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER shots
EXPOSE 8090
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/health')" || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
