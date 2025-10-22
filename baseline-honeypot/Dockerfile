FROM python:3.9-slim

WORKDIR /app

# Copy files
COPY api-honeypot.py .
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create log directory
RUN mkdir -p /app/logs

EXPOSE 5000

CMD ["python", "api-honeypot.py"]