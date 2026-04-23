FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY train.py app.py ./

# Copy pre-trained model artifacts if present
COPY model/ ./model/

ENV PORT=5000
ENV MODEL_DIR=/app/model

EXPOSE 5000

CMD ["python", "app.py"]
