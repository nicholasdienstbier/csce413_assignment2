# FROM python:3.11-slim

# WORKDIR /app

# COPY honeypot.py .

# # Create logs directory
# RUN mkdir -p /app/logs

# EXPOSE 22

# CMD ["python", "-u", "honeypot.py"]
FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /app/logs

COPY honeypot.py .

EXPOSE 80

CMD ["python", "-u", "honeypot.py"]
