# Base image
FROM python:3.11-slim AS base

# Set the default environment variables:
ENV CYGOR_PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Set the WORKDIR as an environment variable,
# so that we can re-use it without typing out the whole thing:
ENV APPLICATION_HOME=/opt/cygor

# Set the PATH variable so /root/.local/bin is included in it.
# This is needed for "uv tool install . -e", which is executed later.
ENV PATH=/root/.local/bin:$PATH

WORKDIR $APPLICATION_HOME

# Install runtime + build dependencies:
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    iproute2 \
    masscan \
    net-tools \
    nmap \
    unzip \
    wget \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libnss3 \
    libpango-1.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    libpq-dev \
    postgresql-client \
    build-essential \
    libkrb5-dev \
    libxml2-dev \
    libxslt1-dev \
    xmlsec1 \
    libxmlsec1-dev \
    libffi-dev \
    libssl-dev \
    libjpeg-dev \
    libpng-dev \
    zlib1g-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    pkg-config

# Remove junk to save space:
RUN apt-get autoclean && \
    apt-get clean && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/*

# Copy uv for dependency management:
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

# Install naabu v2.4.0 (architecture-aware for multi-arch builds):
ARG TARGETARCH
RUN NAABU_VERSION="2.4.0" && \
    NAABU_ARCH="${TARGETARCH}" && \
    wget "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${NAABU_ARCH}.zip" -O /tmp/naabu.zip && \
    unzip /tmp/naabu.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/naabu && \
    rm /tmp/naabu.zip

# Copy pyproject.toml to the container
COPY pyproject.toml $APPLICATION_HOME

# Copy cygor's files to the container:
COPY cygor/ $APPLICATION_HOME/cygor/

# Install cygor's dependencies then cygor using uv:
RUN uv sync
RUN uv tool install . -e --force

# Expose the default port:
# This can be overridden by updating the CYGOR_PORT environment variable
EXPOSE ${CYGOR_PORT}

ENTRYPOINT [ "cygor" ]
CMD [ "--help" ]
