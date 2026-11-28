FROM --platform=linux/amd64 debian:trixie-20261123-slim@sha256:ab3b3c8c5159eebfca4376430132d53c4d425f869c765ecbe47177a030da575d

RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6=14.2.0-19 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/prompt-airlock/share/licenses/debian/libstdc++6 \
    && cp /usr/share/doc/libstdc++6/copyright /opt/prompt-airlock/share/licenses/debian/libstdc++6/ \
    && mkdir -p /var/lib/prompt-airlock/audit \
    && chmod 700 /var/lib/prompt-airlock/audit \
    && chown -R 1000:1000 /var/lib/prompt-airlock

COPY --chown=0:0 deploy/gateway/dist/ /opt/prompt-airlock/
COPY --chmod=0755 deploy/gateway/entrypoint.sh /usr/local/bin/prompt-airlock-entrypoint

ENV LD_LIBRARY_PATH=/opt/prompt-airlock/lib

WORKDIR /var/lib/prompt-airlock
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/prompt-airlock-entrypoint"]
CMD ["serve", "/var/lib/prompt-airlock/config.json"]
