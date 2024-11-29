ARG BASE_IMAGE="python:3.12-alpine"
FROM ${BASE_IMAGE}
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY requirements.txt /opt/opencti-connector-alienvault/

RUN cd /opt/opencti-connector-alienvault/ && \
    pip3 install --no-cache-dir -r requirements.txt

# Copy the connector
COPY src /opt/opencti-connector-alienvault

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
