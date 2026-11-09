FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-compile -r requirements.txt \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY app ./app
COPY static ./static

# Never run as root inside the container
USER 10001

# Cloud Run sets $PORT. One worker + threads keeps memory low and the refresh lock effective.
# --timeout 0 lets a refresh run as long as Cloud Run's request timeout allows.
CMD exec gunicorn --bind :${PORT:-8080} --workers 1 --threads 8 --timeout 0 \
    --access-logfile - app.server:app
