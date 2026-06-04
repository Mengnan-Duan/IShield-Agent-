FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 复制后端代码
COPY backend/ /app/backend/

# 创建沙箱目录
RUN mkdir -p /app/backend/sandbox_files /app/backend/logs /app/backend/data

# 设置环境变量默认值
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

EXPOSE 5000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/health', timeout=5)"

CMD ["python", "-m", "backend.app"]
