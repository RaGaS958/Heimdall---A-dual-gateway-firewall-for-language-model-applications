# HEIMDALL middleware. Port 7860 matches Hugging Face Spaces.
FROM python:3.11-slim

RUN useradd -m -u 1000 user
WORKDIR /home/user/app

# fastembed runs on ONNX Runtime, so no PyTorch and no GPU libraries are needed.
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .
# Mount point for the state volume. A named volume copies this folder's owner on first use, so the
# unprivileged user can write the review queue, labels, audit log and model cache.
RUN mkdir -p /home/user/app/state/models && chown -R user:user /home/user/app/state

USER user
ENV HOME=/home/user PATH=/home/user/.local/bin:$PATH PYTHONUNBUFFERED=1 HEIMDALL_ENV=production

EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:7860/health', timeout=4)"
CMD ["uvicorn", "heimdall_app:app", "--host", "0.0.0.0", "--port", "7860", "--no-server-header"]
