FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINELLE_BD=/donnees/sentinelle.db \
    SENTINELLE_DOCS=0
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd --system --uid 1000 sentinelle && mkdir -p /donnees && chown sentinelle /donnees
USER sentinelle
EXPOSE 8000
# --proxy-headers : la vraie adresse IP des visiteurs (transmise par Caddy) sert aux limites anti-abus.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
