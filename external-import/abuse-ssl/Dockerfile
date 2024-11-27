ARG BASE_IMAGE="python:3.12-alpine"
FROM ${BASE_IMAGE}
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-abuse-ssl

# Install Python modules
# hadolint ignore=DL3003
RUN cd /opt/opencti-abuse-ssl && \
    pip3 install --no-cache-dir -r requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

