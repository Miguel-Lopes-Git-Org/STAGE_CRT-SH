# Use a Python version compatible with the pinned dependencies.
FROM python:3.12-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy all files from the current directory to /app in the container
COPY . /app

# Install the Python dependencies listed in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8000 to allow access from outside the container
EXPOSE 8000

# Start the FastAPI application, listening on all network interfaces (0.0.0.0) at port 8000
CMD ["python", "-m", "uvicorn", "main:app", "--app-dir", "app", "--host", "0.0.0.0", "--port", "8000"]
