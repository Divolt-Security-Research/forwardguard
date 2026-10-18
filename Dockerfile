FROM python:3.12-slim

LABEL org.opencontainers.image.title="ForwardGuard"
LABEL org.opencontainers.image.description="Continuous audit tooling for silent email-forwarder detection"
LABEL org.opencontainers.image.source="https://github.com/divolt-security-research/forwardguard"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Divolt Security Research"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

VOLUME /etc/forwardguard
VOLUME /var/lib/forwardguard

ENTRYPOINT ["forwardguard"]
CMD ["--config", "/etc/forwardguard/config.yaml", "--daemon"]
