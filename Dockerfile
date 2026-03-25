FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY pure_backend/requirements.txt ./pure_backend/requirements.txt
RUN pip install --no-cache-dir -r pure_backend/requirements.txt

COPY . .

RUN chmod +x pure_backend/start.sh

EXPOSE 8000

CMD ["sh", "pure_backend/start.sh"]
