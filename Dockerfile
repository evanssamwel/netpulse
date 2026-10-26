# Network Scanner Suite v2.0 Dockerfile
FROM python:3.11-slim

# Install system networking tools and dependencies for raw packet manipulation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iputils-ping \
    net-tools \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and package
COPY scanner.py .
COPY network_scanner/ network_scanner/
COPY tests/ tests/

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Entry point allows executing any scanner command directly
# Note: Host networking (--net=host) and raw socket capabilities (--cap-add=NET_RAW --cap-add=NET_ADMIN)
# are required for Layer 2 ARP and SYN scanning.
ENTRYPOINT ["python", "scanner.py"]
CMD ["--help"]
