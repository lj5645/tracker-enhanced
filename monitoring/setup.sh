#!/bin/bash

echo "=== Aquatic Tracker Monitoring Setup ==="

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl start docker
    systemctl enable docker
fi

# 检查 Docker Compose 是否安装
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose not found. Installing..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# 创建目录
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards

# 进入监控目录
cd monitoring

# 启动服务
echo "Starting Prometheus and Grafana..."
docker-compose up -d

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Services:"
echo "  - Prometheus:  http://localhost:9090"
echo "  - Grafana:     http://localhost:3000"
echo "  - Metrics Proxy (CORS): http://localhost:9001/metrics"
echo ""
echo "Grafana Login:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "To stop services: docker-compose down"
echo "To view logs: docker-compose logs -f"
