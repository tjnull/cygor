# Base image
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CYGOR_PORT=8080

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    git \
    nmap \
    masscan \
    iproute2 \
    net-tools \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Install naabu (latest stable release)
RUN curl -fsSL -o /tmp/naabu.zip \
      https://github.com/projectdiscovery/naabu/releases/download/v2.3.0/naabu_2.3.0_linux_amd64.zip \
    && unzip /tmp/naabu.zip -d /usr/local/bin \
    && rm /tmp/naabu.zip

WORKDIR /app

# Copy Cygor into container
COPY . /app/

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install . \
    && pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium

# Expose the default port (can be overridden with -e CYGOR_PORT=XXXX)
EXPOSE ${CYGOR_PORT}

ENTRYPOINT ["cygor"]
CMD ["--help"]
