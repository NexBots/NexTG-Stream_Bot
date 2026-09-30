FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core.py server.py ./

# Render sets $PORT itself and routes HTTPS traffic to it — server.py
# already reads $PORT (see LISTEN_PORT above) and LISTEN_HOST must be
# 0.0.0.0 (not 127.0.0.1) so it's reachable from outside the container;
# set LISTEN_HOST=0.0.0.0 in Render's environment variables.
CMD ["python3", "server.py"]
