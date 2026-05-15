# Showcase image for NebulaCR demos.
#
# The point is not to be production — it is to give the CVE scanner
# something to find so the dashboards have signal. We pick a base
# image that has known CVEs (parameterised so operators can swap),
# add a couple of pip packages with public advisories, and ship a
# trivial HTTP server.

ARG BASE_IMAGE=python:3.9-slim
FROM ${BASE_IMAGE}

# Tag the base image so 018 lineage detection picks it up.
LABEL org.opencontainers.image.base.name="${BASE_IMAGE}"
LABEL org.opencontainers.image.title="NebulaCR Showcase App"
LABEL org.opencontainers.image.description="Demo image with deliberate CVE-rich deps for showcase runs."
LABEL org.opencontainers.image.source="https://github.com/bwalia/nebulacr"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]
