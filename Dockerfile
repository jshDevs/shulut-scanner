# Dockerfile for SHULUT Scanner
# Security scanner for detecting SHULUT vulnerabilities

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app/

# Make scripts executable
RUN chmod +x /app/shulut-scanner.sh

# Install Python dependencies if requirements.txt exists
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# Set the entrypoint to the scanner script
ENTRYPOINT ["/app/shulut-scanner.sh"]

# Default command (can be overridden)
CMD ["--help"]
