FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (if any needed for pandas, numpy, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirement file and install python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the default Streamlit port
EXPOSE 1500

# Set environment variables for Streamlit
ENV PORT=1500
ENV STREAMLIT_SERVER_PORT=1500
ENV STREAMLIT_SERVER_HEADLESS=true

# Default command runs Streamlit
CMD ["streamlit", "run", "app.py", "--server.port", "1500", "--server.headless", "true"]
