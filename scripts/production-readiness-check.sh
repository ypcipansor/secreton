#!/bin/bash

# Secreton Security System - Production Readiness Checker
# This script validates that the Secreton deployment meets production requirements
# Author: Secreton Security Team
# Version: 1.0.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
SECRETON_API="https://localhost:8200"
CONFIG_DIR="/etc/secreton"
DATA_DIR="/var/lib/secreton"
LOG_DIR="/var/log/secreton"
REQUIRED_MEMORY_GB=16
REQUIRED_DISK_GB=100
REQUIRED_CPU_CORES=8

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Results storage
RESULTS=()

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING:${NC} $1"
    ((WARNING_CHECKS++))
    RESULTS+=("⚠️  $1")
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"
    ((FAILED_CHECKS++))
    RESULTS+=("❌ $1")
}

success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] PASS:${NC} $1"
    ((PASSED_CHECKS++))
    RESULTS+=("✅ $1")
}

check_start() {
    local check_name="$1"
    echo -e "\n${PURPLE}Checking: $check_name${NC}"
    echo "────────────────────────────────────────"
    ((TOTAL_CHECKS++))
}

# System requirements check
check_system_requirements() {
    check_start "System Requirements"
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        success "Operating System: Linux"
    else
        error "Unsupported operating system: $OSTYPE"
    fi
    
    # Check CPU cores
    local cpu_cores=$(nproc)
    if [[ $cpu_cores -ge $REQUIRED_CPU_CORES ]]; then
        success "CPU Cores: $cpu_cores (≥$REQUIRED_CPU_CORES required)"
    else
        error "Insufficient CPU cores: $cpu_cores (≥$REQUIRED_CPU_CORES required)"
    fi
    
    # Check RAM
    local total_memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $total_memory_gb -ge $REQUIRED_MEMORY_GB ]]; then
        success "Memory: ${total_memory_gb}GB (≥${REQUIRED_MEMORY_GB}GB required)"
    else
        error "Insufficient memory: ${total_memory_gb}GB (≥${REQUIRED_MEMORY_GB}GB required)"
    fi
    
    # Check disk space
    local available_disk_gb=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $available_disk_gb -ge $REQUIRED_DISK_GB ]]; then
        success "Disk Space: ${available_disk_gb}GB (≥${REQUIRED_DISK_GB}GB required)"
    else
        error "Insufficient disk space: ${available_disk_gb}GB (≥${REQUIRED_DISK_GB}GB required)"
    fi
}

# Check required software dependencies
check_software_dependencies() {
    check_start "Software Dependencies"
    
    local required_tools=(
        "docker:Docker container runtime"
        "docker-compose:Docker Compose orchestration"
        "openssl:OpenSSL cryptographic library"
        "curl:HTTP client for API testing"
        "jq:JSON processor for API responses"
        "systemctl:Systemd service manager"
    )
    
    for tool_info in "${required_tools[@]}"; do
        local tool=$(echo "$tool_info" | cut -d: -f1)
        local description=$(echo "$tool_info" | cut -d: -f2)
        
        if command -v "$tool" &> /dev/null; then
            local version=""
            case "$tool" in
                "docker") version=$(docker --version | cut -d' ' -f3 | cut -d',' -f1) ;;
                "openssl") version=$(openssl version | cut -d' ' -f2) ;;
                *) version="installed" ;;
            esac
            success "$description: $version"
        else
            error "$description not found: $tool"
        fi
    done
}

# Check file system structure
check_file_system() {
    check_start "File System Structure"
    
    local required_dirs=(
        "$CONFIG_DIR:Configuration directory"
        "$DATA_DIR:Data directory" 
        "$LOG_DIR:Log directory"
        "/opt/secreton:Installation directory"
    )
    
    for dir_info in "${required_dirs[@]}"; do
        local dir=$(echo "$dir_info" | cut -d: -f1)
        local description=$(echo "$dir_info" | cut -d: -f2)
        
        if [[ -d "$dir" ]]; then
            local permissions=$(stat -c %a "$dir")
            local owner=$(stat -c %U:%G "$dir")
            success "$description exists: $dir ($permissions, $owner)"
        else
            error "$description missing: $dir"
        fi
    done
    
    # Check for sensitive file permissions
    local sensitive_files=(
        "$CONFIG_DIR/security.toml:600"
        "$CONFIG_DIR/secrets/postgres_password:600"
        "$CONFIG_DIR/certs/server-key.pem:600"
    )
    
    for file_info in "${sensitive_files[@]}"; do
        local file=$(echo "$file_info" | cut -d: -f1)
        local expected_perm=$(echo "$file_info" | cut -d: -f2)
        
        if [[ -f "$file" ]]; then
            local actual_perm=$(stat -c %a "$file")
            if [[ "$actual_perm" == "$expected_perm" ]]; then
                success "Secure permissions: $file ($actual_perm)"
            else
                error "Insecure permissions: $file ($actual_perm, should be $expected_perm)"
            fi
        else
            warn "Sensitive file not found: $file"
        fi
    done
}

# Check network configuration
check_network_configuration() {
    check_start "Network Configuration"
    
    # Check if ports are available
    local required_ports=(8200 8201 5432 6379)
    
    for port in "${required_ports[@]}"; do
        if netstat -tuln | grep -q ":$port "; then
            success "Port $port is in use (service running)"
        else
            warn "Port $port is not in use (service may not be running)"
        fi
    done
    
    # Check firewall configuration
    if command -v ufw &> /dev/null; then
        local ufw_status=$(ufw status | grep -c "8200/tcp.*ALLOW" || echo "0")
        if [[ $ufw_status -gt 0 ]]; then
            success "UFW firewall configured for Secreton"
        else
            warn "UFW firewall may not be configured for Secreton"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        if firewall-cmd --list-ports | grep -q 8200; then
            success "Firewalld configured for Secreton"
        else
            warn "Firewalld may not be configured for Secreton"
        fi
    else
        warn "No supported firewall detected"
    fi
    
    # Check DNS resolution
    if nslookup localhost > /dev/null 2>&1; then
        success "DNS resolution working"
    else
        error "DNS resolution not working"
    fi
}

# Check TLS/SSL certificates
check_certificates() {
    check_start "TLS/SSL Certificates"
    
    local cert_file="$CONFIG_DIR/certs/server-cert.pem"
    local key_file="$CONFIG_DIR/certs/server-key.pem"
    local ca_file="$CONFIG_DIR/certs/ca-cert.pem"
    
    # Check certificate files exist
    if [[ -f "$cert_file" ]]; then
        success "Server certificate found: $cert_file"
        
        # Check certificate validity
        local cert_expiry=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
        local expiry_epoch=$(date -d "$cert_expiry" +%s)
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [[ $days_until_expiry -gt 30 ]]; then
            success "Certificate valid for $days_until_expiry days"
        elif [[ $days_until_expiry -gt 0 ]]; then
            warn "Certificate expires in $days_until_expiry days"
        else
            error "Certificate has expired"
        fi
        
        # Check certificate key strength
        local key_size=$(openssl x509 -in "$cert_file" -noout -text | grep "Public-Key:" | grep -o "[0-9]*" | head -1)
        if [[ $key_size -ge 4096 ]]; then
            success "Certificate key strength: $key_size bits"
        elif [[ $key_size -ge 2048 ]]; then
            warn "Certificate key strength adequate but consider upgrading: $key_size bits"
        else
            error "Certificate key strength too weak: $key_size bits"
        fi
    else
        error "Server certificate not found: $cert_file"
    fi
    
    if [[ -f "$key_file" ]]; then
        success "Private key found: $key_file"
    else
        error "Private key not found: $key_file"
    fi
    
    if [[ -f "$ca_file" ]]; then
        success "CA certificate found: $ca_file"
    else
        error "CA certificate not found: $ca_file"
    fi
}

# Check service status
check_services() {
    check_start "Service Status"
    
    # Check systemd service
    if systemctl is-active --quiet secreton.service; then
        success "Secreton service is active"
    else
        error "Secreton service is not active"
    fi
    
    if systemctl is-enabled --quiet secreton.service; then
        success "Secreton service is enabled"
    else
        warn "Secreton service is not enabled for auto-start"
    fi
    
    # Check Docker containers
    local running_containers=$(docker ps --filter "name=secreton" --format "{{.Names}}" | wc -l)
    if [[ $running_containers -gt 0 ]]; then
        success "Secreton containers running: $running_containers"
        
        # List running containers
        docker ps --filter "name=secreton" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | while read -r line; do
            if [[ "$line" != *"NAMES"* ]]; then
                log "  $line"
            fi
        done
    else
        error "No Secreton containers are running"
    fi
}

# Check API health
check_api_health() {
    check_start "API Health"
    
    # Test API connectivity
    if curl -s -k "$SECRETON_API/v1/sys/health" > /dev/null; then
        success "API endpoint accessible"
        
        # Get detailed health information
        local health_response=$(curl -s -k "$SECRETON_API/v1/sys/health")
        local sealed=$(echo "$health_response" | jq -r '.sealed // "unknown"')
        local initialized=$(echo "$health_response" | jq -r '.initialized // "unknown"')
        local standby=$(echo "$health_response" | jq -r '.standby // "unknown"')
        local version=$(echo "$health_response" | jq -r '.version // "unknown"')
        
        if [[ "$sealed" == "false" ]]; then
            success "Vault is unsealed"
        else
            error "Vault is sealed"
        fi
        
        if [[ "$initialized" == "true" ]]; then
            success "Vault is initialized"
        else
            error "Vault is not initialized"
        fi
        
        if [[ "$standby" == "false" ]]; then
            success "Vault is active (not in standby)"
        else
            warn "Vault is in standby mode"
        fi
        
        if [[ "$version" != "unknown" ]]; then
            success "Vault version: $version"
        else
            warn "Could not determine vault version"
        fi
    else
        error "API endpoint not accessible at $SECRETON_API"
    fi
}

# Check security configuration
check_security_configuration() {
    check_start "Security Configuration"
    
    # Check security.toml configuration
    local security_config="$CONFIG_DIR/security.toml"
    if [[ -f "$security_config" ]]; then
        success "Security configuration file exists"
        
        # Parse key security settings
        if grep -q "level.*=.*banking-grade\|government-grade" "$security_config"; then
            local security_level=$(grep "level.*=" "$security_config" | cut -d'"' -f2)
            success "Security level configured: $security_level"
        else
            warn "Security level not properly configured"
        fi
        
        if grep -q "quantum_safe_enabled.*=.*true" "$security_config"; then
            success "Quantum-safe cryptography enabled"
        else
            warn "Quantum-safe cryptography not enabled"
        fi
        
        if grep -q "threat_intelligence_enabled.*=.*true" "$security_config"; then
            success "Threat intelligence enabled"
        else
            warn "Threat intelligence not enabled"
        fi
        
        if grep -q "hsm.*enabled.*=.*true" "$security_config"; then
            success "HSM integration enabled"
        else
            warn "HSM integration not enabled"
        fi
    else
        error "Security configuration file not found: $security_config"
    fi
    
    # Check for default passwords
    local secrets_dir="$CONFIG_DIR/secrets"
    if [[ -d "$secrets_dir" ]]; then
        success "Secrets directory exists"
        
        local secret_files=("postgres_password" "redis_password" "grafana_password")
        for secret_file in "${secret_files[@]}"; do
            local secret_path="$secrets_dir/$secret_file"
            if [[ -f "$secret_path" ]]; then
                local secret_length=$(wc -c < "$secret_path")
                if [[ $secret_length -gt 20 ]]; then
                    success "Strong secret configured: $secret_file"
                else
                    warn "Weak secret detected: $secret_file"
                fi
            else
                error "Secret file missing: $secret_file"
            fi
        done
    else
        error "Secrets directory not found: $secrets_dir"
    fi
}

# Check monitoring and logging
check_monitoring_logging() {
    check_start "Monitoring & Logging"
    
    # Check log files
    local log_files=(
        "$LOG_DIR/secreton.log:Main application log"
        "$LOG_DIR/security-monitor.log:Security monitoring log"
        "$LOG_DIR/audit.log:Audit log"
    )
    
    for log_info in "${log_files[@]}"; do
        local log_file=$(echo "$log_info" | cut -d: -f1)
        local description=$(echo "$log_info" | cut -d: -f2)
        
        if [[ -f "$log_file" ]]; then
            local log_size=$(du -h "$log_file" | cut -f1)
            success "$description exists: $log_size"
        else
            warn "$description not found: $log_file"
        fi
    done
    
    # Check log rotation
    if [[ -f "/etc/logrotate.d/secreton" ]]; then
        success "Log rotation configured"
    else
        warn "Log rotation not configured"
    fi
    
    # Check monitoring endpoints
    local monitoring_endpoints=(
        "http://localhost:9090:Prometheus"
        "http://localhost:3000:Grafana"
    )
    
    for endpoint_info in "${monitoring_endpoints[@]}"; do
        local endpoint=$(echo "$endpoint_info" | cut -d: -f1-2)
        local service=$(echo "$endpoint_info" | cut -d: -f3)
        
        if curl -s "$endpoint" > /dev/null; then
            success "$service monitoring accessible"
        else
            warn "$service monitoring not accessible at $endpoint"
        fi
    done
}

# Check backup configuration
check_backup_configuration() {
    check_start "Backup Configuration"
    
    # Check backup script
    if [[ -f "/usr/local/bin/secreton-backup" ]]; then
        success "Backup script installed"
        
        if [[ -x "/usr/local/bin/secreton-backup" ]]; then
            success "Backup script is executable"
        else
            error "Backup script is not executable"
        fi
    else
        error "Backup script not found"
    fi
    
    # Check backup directory
    local backup_dir="/var/backup/secreton"
    if [[ -d "$backup_dir" ]]; then
        success "Backup directory exists"
        
        local backup_count=$(find "$backup_dir" -name "backup_*" -type d 2>/dev/null | wc -l)
        if [[ $backup_count -gt 0 ]]; then
            success "Backup history found: $backup_count backups"
        else
            warn "No backup history found"
        fi
    else
        warn "Backup directory not found: $backup_dir"
    fi
    
    # Check backup cron job
    if crontab -l 2>/dev/null | grep -q "secreton-backup"; then
        success "Backup cron job configured"
    else
        warn "Backup cron job not configured"
    fi
}

# Check performance and resources
check_performance() {
    check_start "Performance & Resources"
    
    # Check CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F% '{print $1}')
    if (( $(echo "$cpu_usage < 80" | bc -l) )); then
        success "CPU usage acceptable: ${cpu_usage}%"
    else
        warn "High CPU usage: ${cpu_usage}%"
    fi
    
    # Check memory usage
    local memory_usage=$(free | awk '/Mem/{printf("%.1f"), $3/$2*100}')
    if (( $(echo "$memory_usage < 85" | bc -l) )); then
        success "Memory usage acceptable: ${memory_usage}%"
    else
        warn "High memory usage: ${memory_usage}%"
    fi
    
    # Check disk usage
    local disk_usage=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
    if [[ $disk_usage -lt 80 ]]; then
        success "Disk usage acceptable: ${disk_usage}%"
    else
        warn "High disk usage: ${disk_usage}%"
    fi
    
    # Check load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local cpu_cores=$(nproc)
    if (( $(echo "$load_avg < $cpu_cores" | bc -l) )); then
        success "Load average acceptable: $load_avg (${cpu_cores} cores)"
    else
        warn "High load average: $load_avg (${cpu_cores} cores)"
    fi
}

# Generate summary report
generate_summary() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                         PRODUCTION READINESS SUMMARY                        ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${GREEN}Total Checks:${NC} $TOTAL_CHECKS"
    echo -e "${GREEN}Passed:${NC} $PASSED_CHECKS"
    echo -e "${YELLOW}Warnings:${NC} $WARNING_CHECKS"
    echo -e "${RED}Failed:${NC} $FAILED_CHECKS"
    
    local success_rate=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    
    echo -e "\n${GREEN}Success Rate:${NC} ${success_rate}%"
    
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        if [[ $WARNING_CHECKS -eq 0 ]]; then
            echo -e "\n${GREEN}🎉 PRODUCTION READY!${NC}"
            echo -e "${GREEN}Secreton is fully configured and ready for production deployment.${NC}"
        else
            echo -e "\n${YELLOW}⚠️  PRODUCTION READY WITH WARNINGS${NC}"
            echo -e "${YELLOW}Secreton is ready for production but has some non-critical issues to address.${NC}"
        fi
    else
        echo -e "\n${RED}❌ NOT PRODUCTION READY${NC}"
        echo -e "${RED}Critical issues must be resolved before production deployment.${NC}"
    fi
    
    # Detailed results
    if [[ ${#RESULTS[@]} -gt 0 ]]; then
        echo -e "\n${PURPLE}Detailed Results:${NC}"
        echo "────────────────────────"
        for result in "${RESULTS[@]}"; do
            echo "  $result"
        done
    fi
    
    # Recommendations
    echo -e "\n${PURPLE}Recommendations:${NC}"
    echo "─────────────────"
    
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        echo -e "${RED}• Address all critical errors before deployment${NC}"
        echo -e "${RED}• Verify system requirements and dependencies${NC}"
        echo -e "${RED}• Check service configuration and startup${NC}"
    fi
    
    if [[ $WARNING_CHECKS -gt 0 ]]; then
        echo -e "${YELLOW}• Review and address warnings for optimal security${NC}"
        echo -e "${YELLOW}• Consider enabling advanced security features${NC}"
        echo -e "${YELLOW}• Verify monitoring and backup configurations${NC}"
    fi
    
    echo -e "${GREEN}• Perform load testing before production traffic${NC}"
    echo -e "${GREEN}• Set up monitoring and alerting${NC}"
    echo -e "${GREEN}• Establish backup and recovery procedures${NC}"
    echo -e "${GREEN}• Conduct security penetration testing${NC}"
    echo -e "${GREEN}• Train operations team on Secreton management${NC}"
    
    # Return appropriate exit code
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        exit 1
    elif [[ $WARNING_CHECKS -gt 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

# Main execution
main() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    SECRETON PRODUCTION READINESS CHECKER                      ║${NC}"
    echo -e "${BLUE}║                         Advanced Security System                             ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    log "Starting production readiness assessment..."
    log "Timestamp: $(date -Iseconds)"
    log "Hostname: $(hostname)"
    log "Kernel: $(uname -r)"
    
    # Run all checks
    check_system_requirements
    check_software_dependencies
    check_file_system
    check_network_configuration
    check_certificates
    check_services
    check_api_health
    check_security_configuration
    check_monitoring_logging
    check_backup_configuration
    check_performance
    
    # Generate final summary
    generate_summary
}

# Execute main function
main "$@"
