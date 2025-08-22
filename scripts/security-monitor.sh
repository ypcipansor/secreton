#!/bin/bash

# Secreton Security Monitoring and Incident Response Script
# This script provides real-time security monitoring and automated incident response
# Author: Secreton Security Team
# Version: 1.0.0

set -euo pipefail

# Configuration
SECRETON_API="https://localhost:8200"
MONITORING_INTERVAL=${MONITORING_INTERVAL:-30}  # seconds
ALERT_THRESHOLD_FAILED_LOGINS=${ALERT_THRESHOLD_FAILED_LOGINS:-10}
ALERT_THRESHOLD_ANOMALY_SCORE=${ALERT_THRESHOLD_ANOMALY_SCORE:-0.8}
ALERT_WEBHOOK_URL=${ALERT_WEBHOOK_URL:-""}
EMAIL_ALERTS=${EMAIL_ALERTS:-"security@company.com"}
EMERGENCY_CONTACT=${EMERGENCY_CONTACT:-""}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/secreton/security-monitor.log"
ALERT_LOG="/var/log/secreton/security-alerts.log"

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[$timestamp]${NC} $message" | tee -a "$LOG_FILE"
}

warn() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[$timestamp] WARNING:${NC} $message" | tee -a "$LOG_FILE"
}

error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[$timestamp] ERROR:${NC} $message" | tee -a "$LOG_FILE"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local alert_msg="[$timestamp] ALERT [$severity]: $message"
    
    echo -e "${RED}$alert_msg${NC}" | tee -a "$ALERT_LOG"
    
    # Send webhook alert
    if [[ -n "$ALERT_WEBHOOK_URL" ]]; then
        send_webhook_alert "$severity" "$message"
    fi
    
    # Send email alert for critical incidents
    if [[ "$severity" == "CRITICAL" && -n "$EMAIL_ALERTS" ]]; then
        send_email_alert "$message"
    fi
    
    # Emergency notification for critical incidents
    if [[ "$severity" == "CRITICAL" && -n "$EMERGENCY_CONTACT" ]]; then
        send_emergency_notification "$message"
    fi
}

# Send webhook alert
send_webhook_alert() {
    local severity="$1"
    local message="$2"
    
    curl -s -X POST "$ALERT_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{
            \"text\": \"Secreton Security Alert\",
            \"attachments\": [{
                \"color\": \"$([ "$severity" == "CRITICAL" ] && echo "danger" || echo "warning")\",
                \"fields\": [{
                    \"title\": \"Severity\",
                    \"value\": \"$severity\",
                    \"short\": true
                }, {
                    \"title\": \"Message\",
                    \"value\": \"$message\",
                    \"short\": false
                }, {
                    \"title\": \"Timestamp\",
                    \"value\": \"$(date -Iseconds)\",
                    \"short\": true
                }]
            }]
        }" || true
}

# Send email alert
send_email_alert() {
    local message="$1"
    
    {
        echo "Subject: CRITICAL: Secreton Security Alert"
        echo "To: $EMAIL_ALERTS"
        echo "Content-Type: text/html; charset=UTF-8"
        echo ""
        echo "<html><body>"
        echo "<h2 style='color: red;'>CRITICAL Security Alert</h2>"
        echo "<p><strong>System:</strong> Secreton Advanced Security Vault</p>"
        echo "<p><strong>Timestamp:</strong> $(date -Iseconds)</p>"
        echo "<p><strong>Alert:</strong> $message</p>"
        echo "<p>Please investigate immediately and take appropriate action.</p>"
        echo "</body></html>"
    } | sendmail "$EMAIL_ALERTS" || true
}

# Send emergency notification
send_emergency_notification() {
    local message="$1"
    
    # This would typically integrate with your emergency notification system
    # For now, we'll use a simple SMS API call (replace with your provider)
    if command -v twilio &> /dev/null; then
        twilio api:core:messages:create \
            --to "$EMERGENCY_CONTACT" \
            --from "+1234567890" \
            --body "CRITICAL Secreton Security Alert: $message" || true
    fi
}

# Get Secreton API token
get_api_token() {
    # In production, this should use a service account or machine token
    local token_file="/etc/secreton/monitor-token"
    if [[ -f "$token_file" ]]; then
        cat "$token_file"
    else
        echo ""
    fi
}

# Check system health
check_system_health() {
    local token=$(get_api_token)
    
    # Check Secreton health
    local health_response=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/health" 2>/dev/null || echo "{}")
    local sealed=$(echo "$health_response" | jq -r '.sealed // "unknown"')
    local initialized=$(echo "$health_response" | jq -r '.initialized // "unknown"')
    
    if [[ "$sealed" == "true" ]]; then
        alert "CRITICAL" "Secreton is sealed - service unavailable"
        return 1
    elif [[ "$initialized" == "false" ]]; then
        alert "HIGH" "Secreton is not initialized"
        return 1
    fi
    
    # Check performance metrics
    local perf_response=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/metrics?format=prometheus" 2>/dev/null || echo "")
    
    if [[ -n "$perf_response" ]]; then
        # Parse key metrics
        local cpu_usage=$(echo "$perf_response" | grep "secreton_runtime_cpu_seconds_total" | tail -1 | awk '{print $2}' | cut -d'.' -f1)
        local memory_usage=$(echo "$perf_response" | grep "secreton_runtime_alloc_bytes" | tail -1 | awk '{print $2}')
        local request_rate=$(echo "$perf_response" | grep "secreton_core_handle_request_count" | tail -1 | awk '{print $2}')
        
        # Alert on high resource usage
        if [[ -n "$cpu_usage" && "$cpu_usage" -gt 80 ]]; then
            alert "HIGH" "High CPU usage detected: ${cpu_usage}%"
        fi
        
        if [[ -n "$memory_usage" && "$memory_usage" -gt 8000000000 ]]; then # 8GB
            alert "HIGH" "High memory usage detected: $((memory_usage/1024/1024/1024))GB"
        fi
    fi
    
    return 0
}

# Monitor security events
monitor_security_events() {
    local token=$(get_api_token)
    
    # Check authentication failures
    local auth_failures=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/audit/failures?limit=100" 2>/dev/null | \
        jq -r '.data.failures // []' | \
        jq 'length')
    
    if [[ "$auth_failures" -gt "$ALERT_THRESHOLD_FAILED_LOGINS" ]]; then
        alert "HIGH" "High number of authentication failures detected: $auth_failures in last monitoring cycle"
        
        # Get failure details for analysis
        local failure_details=$(curl -s -k -H "X-Vault-Token: $token" \
            "$SECRETON_API/v1/sys/audit/failures?limit=10" 2>/dev/null | \
            jq -r '.data.failures[] | "\(.timestamp): \(.client_ip) - \(.error)"' | \
            head -5)
        
        log "Recent authentication failures:"
        echo "$failure_details" | while read -r line; do
            log "  $line"
        done
    fi
    
    # Check for privilege escalation attempts
    local privilege_events=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/audit/privilege-escalation" 2>/dev/null | \
        jq -r '.data.events // []' | \
        jq 'length')
    
    if [[ "$privilege_events" -gt 0 ]]; then
        alert "CRITICAL" "Privilege escalation attempts detected: $privilege_events events"
    fi
    
    # Check zero-trust violations
    local zero_trust_violations=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/zero-trust/violations" 2>/dev/null | \
        jq -r '.data.violations // []' | \
        jq 'length')
    
    if [[ "$zero_trust_violations" -gt 0 ]]; then
        alert "HIGH" "Zero-trust policy violations detected: $zero_trust_violations violations"
    fi
}

# Monitor threat intelligence
monitor_threat_intelligence() {
    local token=$(get_api_token)
    
    # Check threat intelligence alerts
    local threat_alerts=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/threat-intelligence/alerts" 2>/dev/null | \
        jq -r '.data.alerts // []')
    
    if [[ "$threat_alerts" != "[]" ]]; then
        local alert_count=$(echo "$threat_alerts" | jq 'length')
        local high_severity_count=$(echo "$threat_alerts" | jq '[.[] | select(.severity == "high")] | length')
        local critical_severity_count=$(echo "$threat_alerts" | jq '[.[] | select(.severity == "critical")] | length')
        
        if [[ "$critical_severity_count" -gt 0 ]]; then
            alert "CRITICAL" "Critical threat indicators detected: $critical_severity_count indicators"
        elif [[ "$high_severity_count" -gt 0 ]]; then
            alert "HIGH" "High-severity threat indicators detected: $high_severity_count indicators"
        else
            warn "Threat indicators detected: $alert_count indicators"
        fi
        
        # Log threat details
        echo "$threat_alerts" | jq -r '.[] | "\(.timestamp): \(.indicator) (\(.severity)) - \(.description)"' | \
        while read -r threat; do
            log "Threat: $threat"
        done
    fi
    
    # Check behavioral anomalies
    local anomalies=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/threat-intelligence/anomalies" 2>/dev/null | \
        jq -r '.data.anomalies // []')
    
    if [[ "$anomalies" != "[]" ]]; then
        local high_score_anomalies=$(echo "$anomalies" | \
            jq "[.[] | select(.score > $ALERT_THRESHOLD_ANOMALY_SCORE)] | length")
        
        if [[ "$high_score_anomalies" -gt 0 ]]; then
            alert "HIGH" "High-score behavioral anomalies detected: $high_score_anomalies anomalies"
            
            # Log anomaly details
            echo "$anomalies" | \
                jq -r ".[] | select(.score > $ALERT_THRESHOLD_ANOMALY_SCORE) | \"\(.timestamp): \(.user_id) - Score: \(.score) - \(.description)\"" | \
            while read -r anomaly; do
                log "Anomaly: $anomaly"
            done
        fi
    fi
}

# Monitor HSM status
monitor_hsm_status() {
    local token=$(get_api_token)
    
    local hsm_status=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/hsm/status" 2>/dev/null | \
        jq -r '.data.status // "unknown"')
    
    if [[ "$hsm_status" != "healthy" ]]; then
        alert "CRITICAL" "HSM status unhealthy: $hsm_status"
    fi
    
    # Check HSM key availability
    local key_count=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/hsm/keys" 2>/dev/null | \
        jq -r '.data.keys // []' | \
        jq 'length')
    
    if [[ "$key_count" -eq 0 ]]; then
        alert "CRITICAL" "No HSM keys available"
    fi
}

# Monitor compliance status
monitor_compliance() {
    local token=$(get_api_token)
    
    local compliance_status=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/compliance/status" 2>/dev/null | \
        jq -r '.data // {}')
    
    # Check critical compliance frameworks
    local pci_compliant=$(echo "$compliance_status" | jq -r '.pci_dss_compliant // false')
    local sox_compliant=$(echo "$compliance_status" | jq -r '.sox_compliant // false')
    local fips_compliant=$(echo "$compliance_status" | jq -r '.fips_140_2_compliant // false')
    
    if [[ "$pci_compliant" == "false" ]]; then
        alert "CRITICAL" "PCI DSS compliance violation detected"
    fi
    
    if [[ "$sox_compliant" == "false" ]]; then
        alert "CRITICAL" "SOX compliance violation detected"
    fi
    
    if [[ "$fips_compliant" == "false" ]]; then
        alert "HIGH" "FIPS 140-2 compliance issue detected"
    fi
}

# Automated incident response
automated_incident_response() {
    local incident_type="$1"
    local severity="$2"
    local details="$3"
    
    log "Initiating automated incident response for: $incident_type"
    
    case "$incident_type" in
        "auth_failures")
            if [[ "$severity" == "CRITICAL" ]]; then
                # Block suspicious IPs
                log "Implementing IP blocking for suspicious authentication attempts"
                # This would integrate with your firewall/WAF
                # block_suspicious_ips
            fi
            ;;
        "privilege_escalation")
            # Immediately revoke suspicious sessions
            log "Revoking suspicious sessions due to privilege escalation attempt"
            # revoke_suspicious_sessions
            ;;
        "hsm_failure")
            # Switch to backup HSM
            log "HSM failure detected - initiating failover procedures"
            # initiate_hsm_failover
            ;;
        "compliance_violation")
            # Generate immediate compliance report
            log "Compliance violation detected - generating incident report"
            # generate_compliance_incident_report
            ;;
    esac
}

# Generate security report
generate_security_report() {
    local report_file="/var/log/secreton/security-report-$(date +%Y%m%d_%H%M%S).json"
    local token=$(get_api_token)
    
    log "Generating security report: $report_file"
    
    # Collect comprehensive security data
    local health_data=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/health" 2>/dev/null || echo "{}")
    local metrics_data=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/metrics?format=json" 2>/dev/null || echo "{}")
    local audit_summary=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/audit/summary" 2>/dev/null || echo "{}")
    local threat_summary=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/threat-intelligence/summary" 2>/dev/null || echo "{}")
    local compliance_status=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/compliance/status" 2>/dev/null || echo "{}")
    
    # Create comprehensive report
    jq -n --argjson health "$health_data" \
          --argjson metrics "$metrics_data" \
          --argjson audit "$audit_summary" \
          --argjson threats "$threat_summary" \
          --argjson compliance "$compliance_status" \
          '{
            "report_timestamp": now,
            "report_type": "security_status",
            "system_health": $health,
            "performance_metrics": $metrics,
            "audit_summary": $audit,
            "threat_intelligence": $threats,
            "compliance_status": $compliance,
            "monitoring_period": "last_24h"
          }' > "$report_file"
    
    log "Security report generated: $report_file"
}

# Display monitoring dashboard
display_dashboard() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    SECRETON SECURITY MONITORING DASHBOARD                     ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local token=$(get_api_token)
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${GREEN}Current Time:${NC} $timestamp"
    echo -e "${GREEN}Monitoring Interval:${NC} ${MONITORING_INTERVAL}s"
    echo ""
    
    # System Status
    echo -e "${PURPLE}SYSTEM STATUS${NC}"
    echo "─────────────"
    
    local health_response=$(curl -s -k -H "X-Vault-Token: $token" "$SECRETON_API/v1/sys/health" 2>/dev/null || echo "{}")
    local sealed=$(echo "$health_response" | jq -r '.sealed // "unknown"')
    local initialized=$(echo "$health_response" | jq -r '.initialized // "unknown"')
    local standby=$(echo "$health_response" | jq -r '.standby // "unknown"')
    
    if [[ "$sealed" == "false" && "$initialized" == "true" ]]; then
        echo -e "Service Status: ${GREEN}HEALTHY${NC}"
    else
        echo -e "Service Status: ${RED}UNHEALTHY${NC} (sealed: $sealed, initialized: $initialized)"
    fi
    
    echo -e "Standby Mode: $([ "$standby" == "false" ] && echo "${GREEN}ACTIVE${NC}" || echo "${YELLOW}STANDBY${NC}")"
    echo ""
    
    # Security Metrics
    echo -e "${PURPLE}SECURITY METRICS${NC}"
    echo "────────────────"
    
    # Get recent alerts count
    local recent_alerts=$(grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | wc -l || echo "0")
    local critical_alerts=$(grep "CRITICAL" "$ALERT_LOG" 2>/dev/null | grep "$(date '+%Y-%m-%d')" | wc -l || echo "0")
    
    echo -e "Alerts Today: $recent_alerts (${RED}$critical_alerts critical${NC})"
    
    # Threat Intelligence
    local threat_score=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/threat-intelligence/current-risk" 2>/dev/null | \
        jq -r '.data.risk_score // 0.0')
    
    echo -e "Current Threat Level: $(format_threat_level "$threat_score")"
    
    # Compliance Status
    local compliance_score=$(curl -s -k -H "X-Vault-Token: $token" \
        "$SECRETON_API/v1/sys/compliance/score" 2>/dev/null | \
        jq -r '.data.overall_score // 0.0')
    
    echo -e "Compliance Score: $(format_compliance_score "$compliance_score")"
    echo ""
    
    # Recent Activity
    echo -e "${PURPLE}RECENT ACTIVITY${NC}"
    echo "───────────────"
    tail -n 5 "$ALERT_LOG" 2>/dev/null | while read -r line; do
        echo "  $line"
    done
    echo ""
    
    echo -e "${BLUE}Press Ctrl+C to stop monitoring${NC}"
}

# Format threat level for display
format_threat_level() {
    local score="$1"
    local level=""
    local color=""
    
    if (( $(echo "$score < 0.3" | bc -l) )); then
        level="LOW"
        color="$GREEN"
    elif (( $(echo "$score < 0.7" | bc -l) )); then
        level="MEDIUM"
        color="$YELLOW"
    else
        level="HIGH"
        color="$RED"
    fi
    
    echo -e "${color}${level}${NC} ($score)"
}

# Format compliance score for display
format_compliance_score() {
    local score="$1"
    local color=""
    
    if (( $(echo "$score > 0.95" | bc -l) )); then
        color="$GREEN"
    elif (( $(echo "$score > 0.85" | bc -l) )); then
        color="$YELLOW"
    else
        color="$RED"
    fi
    
    echo -e "${color}${score}${NC}"
}

# Main monitoring loop
main_monitor_loop() {
    log "Starting Secreton security monitoring..."
    
    # Ensure log files exist
    touch "$LOG_FILE" "$ALERT_LOG"
    
    while true; do
        if [[ "$1" == "--dashboard" ]]; then
            display_dashboard
        fi
        
        # Run monitoring checks
        if check_system_health; then
            monitor_security_events
            monitor_threat_intelligence
            monitor_hsm_status
            monitor_compliance
        fi
        
        # Generate daily report at midnight
        if [[ $(date +%H:%M) == "00:00" ]]; then
            generate_security_report
        fi
        
        if [[ "$1" != "--dashboard" ]]; then
            log "Monitoring cycle completed - next check in ${MONITORING_INTERVAL}s"
        fi
        
        sleep "$MONITORING_INTERVAL"
    done
}

# Script entry point
case "${1:-monitor}" in
    "monitor")
        main_monitor_loop
        ;;
    "dashboard")
        main_monitor_loop --dashboard
        ;;
    "report")
        generate_security_report
        ;;
    "test-alert")
        alert "HIGH" "Test alert from security monitoring system"
        ;;
    *)
        echo "Usage: $0 {monitor|dashboard|report|test-alert}"
        echo "  monitor    - Run continuous security monitoring"
        echo "  dashboard  - Run monitoring with real-time dashboard"
        echo "  report     - Generate security report"
        echo "  test-alert - Send test alert"
        exit 1
        ;;
esac
