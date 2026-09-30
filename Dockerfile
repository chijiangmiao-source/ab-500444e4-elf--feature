FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# 纯标准库实现，无第三方依赖；仅拷贝运行与验收所需内容
COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2); sys.exit(0 if json.load(r).get('status')=='ok' else 1)"

CMD ["python", "-m", "app.server"]
