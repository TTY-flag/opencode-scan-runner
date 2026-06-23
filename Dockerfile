FROM smanx/opencode:latest

WORKDIR /runner

COPY runner/ /runner/

USER root

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      python3 \
      util-linux \
      uuid-runtime \
      wget \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x /runner/entrypoint.sh \
    && groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --create-home --home-dir /home/scanner --shell /usr/sbin/nologin scanner \
    && mkdir -p /scan/project /scan/opencode /scan/output /home/scanner \
    && chown -R scanner:scanner /runner /scan /home/scanner

USER scanner

ENV HOME=/home/scanner

ENTRYPOINT ["/runner/entrypoint.sh"]
