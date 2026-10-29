FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# cryptg makes Telegram's AES several times faster. Optional: if no prebuilt
# wheel exists for this platform, the build must still succeed without it.
RUN pip install --no-cache-dir cryptg || echo "cryptg not installed, continuing without it"
# uvloop: a much faster asyncio event loop. Optional, server.py falls back to the standard one.
RUN pip install --no-cache-dir uvloop || echo "uvloop not installed, continuing without it"
# Print (in the build log) whether the fast AES made it in. If this says MISSING, Telegram downloads decrypt
# in pure Python at a few hundred KB/s and videos will stutter whatever else you tune.
RUN python3 -c "import cryptg; print('BUILD CHECK: cryptg OK (fast AES)')" || echo "BUILD CHECK: cryptg MISSING - downloads will be very slow"
ENV PYTHONUNBUFFERED=1

COPY core.py server.py ./

# Render sets $PORT itself and routes HTTPS traffic to it — server.py
# already reads $PORT (see LISTEN_PORT above) and LISTEN_HOST must be
# 0.0.0.0 (not 127.0.0.1) so it's reachable from outside the container;
# set LISTEN_HOST=0.0.0.0 in Render's environment variables.
CMD ["python3", "server.py"]
