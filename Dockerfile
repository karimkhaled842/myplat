# Intentionally insecure container so trivy (config) + checkov flag it:
#   - outdated/EOL base image (python:3.9)
#   - runs as root (no USER directive)
#   - no HEALTHCHECK
#   - pip install as root, world-writable app dir
# The seeded app deps also need this older base to import cleanly.
FROM python:3.9

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE 5000

# gunicorn would be the prod-grade server; we use Flask's dev server on purpose.
CMD ["python", "app.py"]
