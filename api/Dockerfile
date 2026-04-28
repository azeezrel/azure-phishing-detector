FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY api/ ./api/
COPY model/ ./model/

# Expose port
EXPOSE 8000

# Run API
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]