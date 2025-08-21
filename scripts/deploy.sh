#!/bin/bash

# Brankas Advanced Security System - Production Deployment Script
# This script automates the deployment of Brankas with advanced security features
# Author: Brankas Security Team
# Version: 1.0.0

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Configuration
DEPLOYMENT_ENV=${DEPLOYMENT_ENV:-production}
BRANKAS_VERSION=${BRANKAS_VERSION:-latest}
SECURITY_LEVEL=${SECURITY_LEVEL:-banking-grade} # banking-grade or government-grade
HSM_ENABLED=${HSM_ENABLED:-true}
QUANTUM_SAFE_ENABLED=${QUANTUM_SAFE_ENABLED:-true}
THREAT_INTELLIGENCE_ENABLED=${THREAT_INTELLIGENCE_ENABLED:-true}

# Directories
DEPLOY_DIR="/opt/brankas"
CONFIG_DIR="/etc/brankas"
LOG_DIR="/var/log/brankas"
DATA_DIR="/var/lib/brankas"
BACKUP_DIR="/var/backup/brankas"

log "Starting Brankas Advanced Security System Deployment"
log "Environment: $DEPLOYMENT_ENV"
log "Security Level: $SECURITY_LEVEL"
log "Version: $BRANKAS_VERSION"

# Check system requirements
check_system_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        error "This deployment script is designed for Linux systems only"
    fi
    
    # Check CPU architecture for quantum-safe crypto
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]] && [[ "$ARCH" != "aarch64" ]]; then
        warn "Quantum-safe cryptography may have limited performance on $ARCH architecture"
    fi
    
    # Check RAM (minimum 8GB for banking-grade, 16GB for government-grade)
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    MIN_RAM=8
    if [[ "$SECURITY_LEVEL" == "government-grade" ]]; then
        MIN_RAM=16
    fi
    
    if [[ $TOTAL_RAM -lt $MIN_RAM ]]; then
        error "Insufficient RAM. Required: ${MIN_RAM}GB, Available: ${TOTAL_RAM}GB"
    fi
    
    # Check disk space (minimum 100GB)
    AVAILABLE_SPACE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $AVAILABLE_SPACE -lt 100 ]]; then
        error "Insufficient disk space. Required: 100GB, Available: ${AVAILABLE_SPACE}GB"
    fi
    
    # Check for required tools
    for tool in docker docker-compose openssl curl jq systemctl; do
        if ! command -v $tool &> /dev/null; then
            error "$tool is required but not installed"
        fi
    done
    
    log "✓ System requirements check passed"
}

# Setup directories and permissions
setup_directories() {
    log "Setting up directory structure..."
    
    for dir in "$DEPLOY_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR"; do
        sudo mkdir -p "$dir"
        sudo chown -R brankas:brankas "$dir"
        sudo chmod 750 "$dir"
    done
    
    # Create secure directories for sensitive data
    sudo mkdir -p "$DATA_DIR/hsm" "$DATA_DIR/keys" "$DATA_DIR/audit"
    sudo chmod 700 "$DATA_DIR/hsm" "$DATA_DIR/keys"
    sudo chmod 755 "$DATA_DIR/audit"
    
    log "✓ Directory structure created"
}

# Create system user
create_system_user() {
    log "Creating system user..."
    
    if ! id "brankas" &>/dev/null; then
        sudo useradd -r -s /bin/false -d "$DATA_DIR" -c "Brankas Security System" brankas
        log "✓ Created brankas system user"
    else
        log "✓ Brankas system user already exists"
    fi
}

# Generate security configuration
generate_security_config() {
    log "Generating security configuration..."
    
    cat > "/tmp/brankas-security.toml" << EOF
[security]
level = "$SECURITY_LEVEL"
enforce_mfa = true
require_hardware_security = true
quantum_safe_enabled = $QUANTUM_SAFE_ENABLED
threat_intelligence_enabled = $THREAT_INTELLIGENCE_ENABLED

[encryption]
algorithm = "AES-256-GCM"
key_derivation = "PBKDF2-SHA256"
key_rotation_interval = "24h"
quantum_safe_algorithms = ["kyber1024", "dilithium5", "falcon1024"]

[hsm]
enabled = $HSM_ENABLED
provider = "softhsm2"  # Change to your HSM provider
slot_id = 0
pin_file = "/etc/brankas/hsm-pin"
fips_mode = true

[mfa]
enabled = true
totp_enabled = true
webauthn_enabled = true
behavioral_biometrics_enabled = true
sms_enabled = false  # Disabled for security reasons
phone_call_enabled = false  # Disabled for security reasons

[zero_trust]
enabled = true
continuous_verification = true
micro_segmentation = true
device_trust_required = true
location_based_policies = true

[audit]
enabled = true
log_level = "debug"
real_time_alerting = true
compliance_reporting = true
log_rotation = "daily"
retention_period = "7y"  # 7 years for banking compliance

[threat_intelligence]
enabled = $THREAT_INTELLIGENCE_ENABLED
feed_update_interval = "5m"
behavioral_analysis = true
ml_anomaly_detection = true
automated_response = true

[compliance]
frameworks = ["PCI-DSS", "SOX", "Basel-III", "GDPR", "FIPS-140-2", "Common-Criteria"]
automated_reporting = true
continuous_monitoring = true

[performance]
max_concurrent_connections = 10000
cache_ttl = "1h"
connection_timeout = "30s"
request_timeout = "60s"

[networking]
tls_min_version = "1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256"
]
perfect_forward_secrecy = true
certificate_pinning = true

[monitoring]
enabled = true
metrics_collection = true
health_check_interval = "30s"
alert_thresholds = { cpu = 80, memory = 85, disk = 90 }

[backup]
enabled = true
encryption_enabled = true
compression_enabled = true
retention_policy = "3-2-1"  # 3 copies, 2 different media, 1 offsite
schedule = "0 2 * * *"  # Daily at 2 AM
EOF

    sudo mv "/tmp/brankas-security.toml" "$CONFIG_DIR/security.toml"
    sudo chown brankas:brankas "$CONFIG_DIR/security.toml"
    sudo chmod 600 "$CONFIG_DIR/security.toml"
    
    log "✓ Security configuration generated"
}

# Generate HSM configuration
setup_hsm() {
    if [[ "$HSM_ENABLED" == "true" ]]; then
        log "Setting up HSM configuration..."
        
        # Install SoftHSM2 for development/testing
        if ! command -v softhsm2-util &> /dev/null; then
            case "$(lsb_release -si)" in
                Ubuntu|Debian)
                    sudo apt-get update
                    sudo apt-get install -y softhsm2
                    ;;
                CentOS|RHEL|Rocky)
                    sudo yum install -y softhsm
                    ;;
                *)
                    warn "Unable to install SoftHSM2 automatically for this OS"
                    ;;
            esac
        fi
        
        # Initialize HSM token
        if [[ ! -f "$CONFIG_DIR/hsm-pin" ]]; then
            HSM_PIN=$(openssl rand -hex 16)
            echo "$HSM_PIN" | sudo tee "$CONFIG_DIR/hsm-pin" > /dev/null
            sudo chmod 600 "$CONFIG_DIR/hsm-pin"
            sudo chown brankas:brankas "$CONFIG_DIR/hsm-pin"
            
            # Initialize token
            echo "$HSM_PIN" | softhsm2-util --init-token --slot 0 --label "Brankas" --pin "$HSM_PIN" --so-pin "$HSM_PIN"
        fi
        
        log "✓ HSM setup completed"
    fi
}

# Generate TLS certificates
generate_certificates() {
    log "Generating TLS certificates..."
    
    CERT_DIR="$CONFIG_DIR/certs"
    sudo mkdir -p "$CERT_DIR"
    
    # Generate CA private key
    sudo openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096
    
    # Generate CA certificate
    sudo openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca-key.pem" -sha256 -out "$CERT_DIR/ca-cert.pem" -subj "/C=US/ST=CA/L=San Francisco/O=Brankas/CN=Brankas CA"
    
    # Generate server private key
    sudo openssl genrsa -out "$CERT_DIR/server-key.pem" 4096
    
    # Generate server certificate request
    sudo openssl req -subj "/C=US/ST=CA/L=San Francisco/O=Brankas/CN=brankas.local" -sha256 -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr"
    
    # Generate server certificate
    sudo openssl x509 -req -days 365 -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/server-cert.pem" -sha256 -CAcreateserial
    
    # Set permissions
    sudo chown -R brankas:brankas "$CERT_DIR"
    sudo chmod 600 "$CERT_DIR"/*.pem
    sudo rm "$CERT_DIR/server.csr"
    
    log "✓ TLS certificates generated"
}

# Create Docker Compose configuration
create_docker_compose() {
    log "Creating Docker Compose configuration..."
    
    cat > "/tmp/docker-compose.yml" << EOF
version: '3.8'

services:
  brankas:
    image: brankas/security-vault:${BRANKAS_VERSION}
    container_name: brankas-vault
    restart: unless-stopped
    ports:
      - "8200:8200"
      - "8201:8201"
    volumes:
      - ${CONFIG_DIR}:/etc/brankas:ro
      - ${DATA_DIR}:/var/lib/brankas
      - ${LOG_DIR}:/var/log/brankas
    environment:
      - BRANKAS_CONFIG_PATH=/etc/brankas
      - BRANKAS_DATA_PATH=/var/lib/brankas
      - BRANKAS_LOG_LEVEL=info
      - BRANKAS_SECURITY_LEVEL=${SECURITY_LEVEL}
    depends_on:
      - postgres
      - redis
    networks:
      - brankas-network
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    healthcheck:
      test: ["CMD-SHELL", "curl -f https://localhost:8200/v1/sys/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    container_name: brankas-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=brankas
      - POSTGRES_USER=brankas
      - POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ${CONFIG_DIR}/postgresql.conf:/etc/postgresql/postgresql.conf
    networks:
      - brankas-network
    secrets:
      - postgres_password
    command: postgres -c config_file=/etc/postgresql/postgresql.conf

  redis:
    image: redis:7-alpine
    container_name: brankas-redis
    restart: unless-stopped
    command: redis-server --requirepass "\$REDIS_PASSWORD" --appendonly yes
    environment:
      - REDIS_PASSWORD_FILE=/run/secrets/redis_password
    volumes:
      - redis_data:/data
    networks:
      - brankas-network
    secrets:
      - redis_password

  threat-intelligence:
    image: brankas/threat-intelligence:${BRANKAS_VERSION}
    container_name: brankas-threat-intel
    restart: unless-stopped
    volumes:
      - ${CONFIG_DIR}:/etc/brankas:ro
      - ${DATA_DIR}/threat-intel:/var/lib/threat-intel
    environment:
      - BRANKAS_CONFIG_PATH=/etc/brankas
    depends_on:
      - postgres
      - redis
    networks:
      - brankas-network

  monitoring:
    image: prom/prometheus:latest
    container_name: brankas-monitoring
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ${CONFIG_DIR}/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - brankas-network

  grafana:
    image: grafana/grafana:latest
    container_name: brankas-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD_FILE=/run/secrets/grafana_password
    volumes:
      - grafana_data:/var/lib/grafana
      - ${CONFIG_DIR}/grafana:/etc/grafana/provisioning
    networks:
      - brankas-network
    secrets:
      - grafana_password

volumes:
  postgres_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${DATA_DIR}/postgres
  redis_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${DATA_DIR}/redis
  prometheus_data:
    driver: local
  grafana_data:
    driver: local

networks:
  brankas-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

secrets:
  postgres_password:
    file: ${CONFIG_DIR}/secrets/postgres_password
  redis_password:
    file: ${CONFIG_DIR}/secrets/redis_password
  grafana_password:
    file: ${CONFIG_DIR}/secrets/grafana_password
EOF

    sudo mv "/tmp/docker-compose.yml" "$DEPLOY_DIR/docker-compose.yml"
    sudo chown brankas:brankas "$DEPLOY_DIR/docker-compose.yml"
    
    log "✓ Docker Compose configuration created"
}

# Generate secrets
generate_secrets() {
    log "Generating secrets..."
    
    SECRETS_DIR="$CONFIG_DIR/secrets"
    sudo mkdir -p "$SECRETS_DIR"
    
    # Generate database passwords
    openssl rand -base64 32 | sudo tee "$SECRETS_DIR/postgres_password" > /dev/null
    openssl rand -base64 32 | sudo tee "$SECRETS_DIR/redis_password" > /dev/null
    openssl rand -base64 32 | sudo tee "$SECRETS_DIR/grafana_password" > /dev/null
    
    # Set permissions
    sudo chown -R brankas:brankas "$SECRETS_DIR"
    sudo chmod 700 "$SECRETS_DIR"
    sudo chmod 600 "$SECRETS_DIR"/*
    
    log "✓ Secrets generated"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    sudo tee /etc/systemd/system/brankas.service > /dev/null << EOF
[Unit]
Description=Brankas Advanced Security Vault
Requires=docker.service
After=docker.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${DEPLOY_DIR}
ExecStartPre=-/usr/bin/docker-compose -f ${DEPLOY_DIR}/docker-compose.yml down
ExecStart=/usr/bin/docker-compose -f ${DEPLOY_DIR}/docker-compose.yml up -d
ExecStop=/usr/bin/docker-compose -f ${DEPLOY_DIR}/docker-compose.yml down
TimeoutStartSec=0
Restart=on-failure
RestartSec=30
User=brankas
Group=brankas

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable brankas.service
    
    log "✓ Systemd service created"
}

# Setup firewall rules
setup_firewall() {
    log "Setting up firewall rules..."
    
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian UFW
        sudo ufw allow 22/tcp    # SSH
        sudo ufw allow 8200/tcp  # Brankas HTTPS
        sudo ufw allow 8201/tcp  # Brankas replication
        sudo ufw --force enable
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL firewalld
        sudo firewall-cmd --permanent --add-port=22/tcp
        sudo firewall-cmd --permanent --add-port=8200/tcp
        sudo firewall-cmd --permanent --add-port=8201/tcp
        sudo firewall-cmd --reload
    else
        warn "No supported firewall found. Please configure firewall manually."
    fi
    
    log "✓ Firewall configured"
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."
    
    sudo tee /etc/logrotate.d/brankas > /dev/null << EOF
${LOG_DIR}/*.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 644 brankas brankas
    postrotate
        /usr/bin/docker-compose -f ${DEPLOY_DIR}/docker-compose.yml exec brankas pkill -SIGUSR1 brankas || true
    endscript
}
EOF
    
    log "✓ Log rotation configured"
}

# Setup monitoring and alerting
setup_monitoring() {
    log "Setting up monitoring and alerting..."
    
    # Prometheus configuration
    cat > "/tmp/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "brankas_rules.yml"

scrape_configs:
  - job_name: 'brankas'
    static_configs:
      - targets: ['brankas:8200']
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    scheme: https
    tls_config:
      ca_file: '/etc/brankas/certs/ca-cert.pem'
      cert_file: '/etc/brankas/certs/server-cert.pem'
      key_file: '/etc/brankas/certs/server-key.pem'
      insecure_skip_verify: false

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

    sudo mv "/tmp/prometheus.yml" "$CONFIG_DIR/prometheus.yml"
    
    # Alerting rules
    cat > "/tmp/brankas_rules.yml" << EOF
groups:
  - name: brankas.rules
    rules:
      - alert: BrankasDown
        expr: up{job="brankas"} == 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Brankas instance is down"
          description: "Brankas has been down for more than 1 minute"

      - alert: BrankasHighMemoryUsage
        expr: (brankas_runtime_alloc_bytes / brankas_runtime_sys_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on Brankas"
          description: "Memory usage is above 85%"

      - alert: BrankasHighCPUUsage
        expr: rate(brankas_runtime_cpu_seconds_total[5m]) * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on Brankas"
          description: "CPU usage is above 80%"
          
      - alert: BrankasSecurityIncident
        expr: rate(brankas_audit_failed_requests_total[1m]) > 10
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Security incident detected"
          description: "High rate of failed authentication attempts"
EOF

    sudo mv "/tmp/brankas_rules.yml" "$CONFIG_DIR/brankas_rules.yml"
    sudo chown brankas:brankas "$CONFIG_DIR/prometheus.yml" "$CONFIG_DIR/brankas_rules.yml"
    
    log "✓ Monitoring configuration created"
}

# Run security hardening
security_hardening() {
    log "Applying security hardening..."
    
    # Disable core dumps
    echo "* soft core 0" | sudo tee -a /etc/security/limits.conf
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
    
    # Set kernel parameters for security
    cat > "/tmp/99-brankas-security.conf" << EOF
# Brankas security hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

    sudo mv "/tmp/99-brankas-security.conf" /etc/sysctl.d/99-brankas-security.conf
    sudo sysctl -p /etc/sysctl.d/99-brankas-security.conf
    
    log "✓ Security hardening applied"
}

# Create backup script
create_backup_script() {
    log "Creating backup script..."
    
    cat > "/tmp/brankas-backup.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="/var/backup/brankas/backup_${BACKUP_DATE}"
CONFIG_DIR="/etc/brankas"
DATA_DIR="/var/lib/brankas"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting Brankas backup..."

# Create backup directory
mkdir -p "$BACKUP_PATH"

# Backup configuration
log "Backing up configuration..."
tar -czf "$BACKUP_PATH/config.tar.gz" -C "$CONFIG_DIR" .

# Backup data (excluding temporary files)
log "Backing up data..."
tar --exclude='*.tmp' --exclude='*.lock' -czf "$BACKUP_PATH/data.tar.gz" -C "$DATA_DIR" .

# Create backup manifest
cat > "$BACKUP_PATH/manifest.json" << MANIFEST
{
    "backup_date": "$BACKUP_DATE",
    "brankas_version": "$(docker images --format '{{.Tag}}' brankas/security-vault | head -1)",
    "config_checksum": "$(sha256sum $BACKUP_PATH/config.tar.gz | cut -d' ' -f1)",
    "data_checksum": "$(sha256sum $BACKUP_PATH/data.tar.gz | cut -d' ' -f1)",
    "backup_size": "$(du -sh $BACKUP_PATH | cut -f1)"
}
MANIFEST

# Encrypt backup if GPG key is available
if [[ -f "/etc/brankas/backup.gpg.key" ]]; then
    log "Encrypting backup..."
    gpg --trust-model always --encrypt -r brankas-backup "$BACKUP_PATH/config.tar.gz"
    gpg --trust-model always --encrypt -r brankas-backup "$BACKUP_PATH/data.tar.gz"
    rm "$BACKUP_PATH/config.tar.gz" "$BACKUP_PATH/data.tar.gz"
fi

# Clean old backups (keep 30 days)
find /var/backup/brankas -name "backup_*" -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null || true

log "Backup completed: $BACKUP_PATH"
EOF

    sudo mv "/tmp/brankas-backup.sh" "/usr/local/bin/brankas-backup"
    sudo chmod +x "/usr/local/bin/brankas-backup"
    
    # Create cron job for daily backups
    echo "0 3 * * * /usr/local/bin/brankas-backup" | sudo tee /etc/cron.d/brankas-backup > /dev/null
    
    log "✓ Backup script created"
}

# Deploy and start services
deploy_services() {
    log "Deploying and starting services..."
    
    cd "$DEPLOY_DIR"
    
    # Pull latest images
    sudo -u brankas docker-compose pull
    
    # Start services
    sudo systemctl start brankas.service
    
    # Wait for services to be healthy
    log "Waiting for services to become healthy..."
    for i in {1..60}; do
        if sudo -u brankas docker-compose ps | grep -q "Up (healthy)"; then
            break
        fi
        sleep 5
    done
    
    # Check service status
    if ! sudo systemctl is-active --quiet brankas.service; then
        error "Failed to start Brankas service"
    fi
    
    log "✓ Services deployed and started successfully"
}

# Run post-deployment validation
post_deployment_validation() {
    log "Running post-deployment validation..."
    
    # Check service health
    if ! curl -sk https://localhost:8200/v1/sys/health | jq -e '.sealed == false' > /dev/null; then
        error "Brankas health check failed"
    fi
    
    # Check security features
    SECURITY_STATUS=$(curl -sk https://localhost:8200/v1/sys/security/status | jq -r '.security_level')
    if [[ "$SECURITY_STATUS" != "$SECURITY_LEVEL" ]]; then
        error "Security level mismatch. Expected: $SECURITY_LEVEL, Got: $SECURITY_STATUS"
    fi
    
    # Run basic functionality test
    TOKEN=$(curl -sk -X POST https://localhost:8200/v1/auth/test/login -d '{"username":"admin","password":"test"}' | jq -r '.auth.client_token')
    if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
        warn "Could not obtain test token - manual initialization required"
    fi
    
    log "✓ Post-deployment validation completed"
}

# Main deployment function
main() {
    log "=== Brankas Advanced Security System Deployment ==="
    
    check_system_requirements
    create_system_user
    setup_directories
    generate_security_config
    setup_hsm
    generate_certificates
    generate_secrets
    create_docker_compose
    create_systemd_service
    setup_firewall
    setup_log_rotation
    setup_monitoring
    security_hardening
    create_backup_script
    deploy_services
    post_deployment_validation
    
    log "=== Deployment Completed Successfully ==="
    log ""
    log "Brankas is now running on https://localhost:8200"
    log "Monitoring dashboard: http://localhost:3000"
    log "Prometheus metrics: http://localhost:9090"
    log ""
    log "Important next steps:"
    log "1. Initialize and unseal Brankas: https://localhost:8200/ui/"
    log "2. Configure authentication methods"
    log "3. Set up policies and secrets"
    log "4. Review monitoring and alerting"
    log "5. Test backup and recovery procedures"
    log ""
    log "Security configuration: $CONFIG_DIR/security.toml"
    log "Logs location: $LOG_DIR"
    log "Data location: $DATA_DIR"
    log ""
    warn "Remember to securely store the root token and unseal keys!"
}

# Execute main function
main "$@"
