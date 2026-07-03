FROM dreamhackofficial/web3-base:2025-04-04

COPY ./deploy/config.yaml /app/
COPY ./deploy/lib/ /app/lib/
COPY ./deploy/src/ /app/src/
COPY ./deploy/verifier.py /app/verifier.py
COPY ./deploy/flag.txt /app/flag.txt

RUN /app/build.sh