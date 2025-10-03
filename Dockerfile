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

# Install dependencies:
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
    libxrandr2

# Remove junk to save space:
RUN apt-get autoclean && \
    apt-get clean && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/*

# Copy uv for dependency management:
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

# Install the latest (stable) version of naabu:
RUN curl -s https://api.github.com/repos/projectdiscovery/naabu/releases/latest | \
    grep "browser_download_url.*linux_amd64.zip" | \
    cut -d : -f 2,3 | \
    tr -d '"' | \
    wget -i - -O /tmp/naabu.zip && \
    unzip /tmp/naabu.zip -d /usr/local/bin && \
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
