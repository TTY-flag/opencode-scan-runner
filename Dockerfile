FROM ghcr.io/anomalyco/opencode:latest

WORKDIR /runner

COPY runner/ /runner/

RUN apk add --no-cache python3 util-linux \
    && chmod +x /runner/entrypoint.sh \
    && addgroup -S scanner \
    && adduser -S -G scanner -u 10001 scanner \
    && mkdir -p /scan/project /scan/opencode /scan/output /home/scanner \
    && chown -R scanner:scanner /runner /scan /home/scanner

USER scanner

ENV HOME=/home/scanner

ENTRYPOINT ["/runner/entrypoint.sh"]
