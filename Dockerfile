FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if any are needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
# Install dependencies using uv
RUN uv pip install --system --no-cache .

COPY src/ src/
RUN uv pip install --system --no-cache .

ENTRYPOINT ["sentinelx"]
CMD ["monitor"]
