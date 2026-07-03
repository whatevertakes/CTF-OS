FROM python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/local/bin/python3 /usr/bin/python3 && \
    ln -sf /usr/local/bin/python3.12 /usr/bin/python3.12 && \
    python3 --version | grep -F "Python 3.12.11" && \
    ldconfig -p | grep -F "libpython3.12.so.1.0"

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN useradd -m ctf

COPY flag /flag
RUN chmod 444 /flag

COPY server.py /challenge/server.py

USER ctf
EXPOSE 31337

CMD ["socat", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:python3 /challenge/server.py,stderr"]
