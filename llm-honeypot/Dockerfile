FROM python:3.9-slim

WORKDIR /app

COPY llm-honeypot-v2.py .
COPY requirements.txt .
COPY .env .
COPY knowledge_base/ ./knowledge_base/

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/logs

EXPOSE 5000

CMD ["python", "llm-honeypot-v2.py"]