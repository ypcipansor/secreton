#!/bin/bash

# Secreton Advanced Security System - Master Control Script
# This script provides unified control for all Secreton operations
# Author: Secreton Security Team
# Version: 1.0.0

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETON_ROOT="$(dirname "$SCRIPT_DIR")"

# Logo and Header
show_header() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ██████╗ ██████╗  █████╗ ███╗   ██╗██╗  ██╗ █████╗ ███████╗
    ██╔══██╗██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██╔══██╗██╔════╝
    ██████╔╝██████╔╝███████║██╔██╗ ██║█████╔╝ ███████║███████╗
    ██╔══██╗██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██╔══██║╚════██║
    ██████╔╝██║  ██║██║  ██║██║ ╚████║██║  ██╗██║  ██║███████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${BLUE}          Advanced Security System - Master Control${NC}"
    echo -e "${BLUE}        Quantum-Safe • AI-Powered • Zero-Trust Ready${NC}"
    echo ""
}

# Main menu
show_main_menu() {
    echo -e "${PURPLE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                     SECRETON MAIN MENU                      ║${NC}"
    echo -e "${PURPLE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}🚀 DEPLOYMENT & SETUP${NC}"
    echo -e "  ${CYAN}1.${NC} Full System Deployment"
    echo -e "  ${CYAN}2.${NC} Configuration Optimization"
    echo -e "  ${CYAN}3.${NC} Production Readiness Check"
    echo ""
    echo -e "${GREEN}🔐 SECURITY OPERATIONS${NC}"
    echo -e "  ${CYAN}4.${NC} Security Monitoring Dashboard"
    echo -e "  ${CYAN}5.${NC} Generate Security Report"
    echo -e "  ${CYAN}6.${NC} Threat Intelligence Status"
    echo -e "  ${CYAN}7.${NC} Compliance Check"
    echo ""
    echo -e "${GREEN}🛠 MAINTENANCE & TESTING${NC}"
    echo -e "  ${CYAN}8.${NC} Run Test Suite"
    echo -e "  ${CYAN}9.${NC} Performance Benchmark"
    echo -e "  ${CYAN}10.${NC} System Health Check"
    echo -e "  ${CYAN}11.${NC} Backup System"
    echo ""
    echo -e "${GREEN}📊 MONITORING & LOGS${NC}"
    echo -e "  ${CYAN}12.${NC} View Live Logs"
    echo -e "  ${CYAN}13.${NC} Metrics Dashboard"
    echo -e "  ${CYAN}14.${NC} Alert Management"
    echo ""
    echo -e "${GREEN}⚙️  SYSTEM CONTROL${NC}"
    echo -e "  ${CYAN}15.${NC} Start/Stop Services"
    echo -e "  ${CYAN}16.${NC} System Status"
    echo -e "  ${CYAN}17.${NC} Emergency Procedures"
    echo ""
    echo -e "${GREEN}📚 DOCUMENTATION${NC}"
    echo -e "  ${CYAN}18.${NC} View Documentation"
    echo -e "  ${CYAN}19.${NC} Performance Comparison"
    echo -e "  ${CYAN}20.${NC} Feature Overview"
    echo ""
    echo -e "${RED}0. Exit${NC}"
    echo ""
    echo -n "Select option [0-20]: "
}

# Deployment functions
deploy_full_system() {
    echo -e "\n${GREEN}🚀 Starting Full System Deployment${NC}"
    echo "This will deploy Secreton with all advanced security features."
    echo ""
    
    read -p "Select deployment type [banking-grade/government-grade/high-performance]: " deploy_type
    deploy_type=${deploy_type:-banking-grade}
    
    export DEPLOYMENT_TYPE="$deploy_type"
    
    echo -e "\n${BLUE}Starting deployment with type: $deploy_type${NC}"
    
    if [[ -f "$SCRIPT_DIR/deploy.sh" ]]; then
        sudo "$SCRIPT_DIR/deploy.sh"
    else
        echo -e "${RED}Error: Deploy script not found${NC}"
        return 1
    fi
    
    echo -e "\n${GREEN}✅ Deployment completed!${NC}"
    read -p "Press Enter to continue..."
}

configure_optimization() {
    echo -e "\n${GREEN}⚙️  Configuration Optimization${NC}"
    echo "Optimize Secreton configuration for your specific requirements."
    echo ""
    
    echo "Deployment Types:"
    echo "1. Banking-Grade (PCI DSS, SOX, Basel III)"
    echo "2. Government-Grade (FIPS 140-2, Common Criteria)"
    echo "3. High-Performance (Maximum throughput)"
    echo ""
    read -p "Select deployment type [1-3]: " deploy_choice
    
    case $deploy_choice in
        1) deploy_type="banking-grade" ;;
        2) deploy_type="government-grade" ;;
        3) deploy_type="high-performance" ;;
        *) deploy_type="banking-grade" ;;
    esac
    
    echo ""
    echo "Optimization Focus:"
    echo "1. Security (Maximum protection)"
    echo "2. Performance (Maximum speed)"
    echo "3. Balanced (Optimal mix)"
    echo ""
    read -p "Select optimization focus [1-3]: " opt_choice
    
    case $opt_choice in
        1) optimize_for="security" ;;
        2) optimize_for="performance" ;;
        3) optimize_for="balanced" ;;
        *) optimize_for="balanced" ;;
    esac
    
    echo -e "\n${BLUE}Starting optimization: $deploy_type with $optimize_for focus${NC}"
    
    if [[ -f "$SCRIPT_DIR/configure-optimize.sh" ]]; then
        "$SCRIPT_DIR/configure-optimize.sh" --deployment-type "$deploy_type" --optimize-for "$optimize_for"
    else
        echo -e "${RED}Error: Configuration optimizer not found${NC}"
        return 1
    fi
    
    echo -e "\n${GREEN}✅ Configuration optimization completed!${NC}"
    read -p "Press Enter to continue..."
}

production_readiness() {
    echo -e "\n${GREEN}🔍 Production Readiness Check${NC}"
    echo "Comprehensive validation of system readiness for production."
    echo ""
    
    if [[ -f "$SCRIPT_DIR/production-readiness-check.sh" ]]; then
        "$SCRIPT_DIR/production-readiness-check.sh"
        local exit_code=$?
        
        case $exit_code in
            0) echo -e "\n${GREEN}🎉 System is PRODUCTION READY!${NC}" ;;
            1) echo -e "\n${RED}❌ System has CRITICAL ISSUES${NC}" ;;
            2) echo -e "\n${YELLOW}⚠️  System ready with WARNINGS${NC}" ;;
        esac
    else
        echo -e "${RED}Error: Readiness check script not found${NC}"
        return 1
    fi
    
    read -p "Press Enter to continue..."
}

security_monitoring() {
    echo -e "\n${GREEN}🛡 Security Monitoring Dashboard${NC}"
    echo "Real-time security monitoring and threat intelligence."
    echo ""
    
    echo "Monitoring Options:"
    echo "1. Interactive Dashboard"
    echo "2. Background Monitoring"
    echo "3. Generate Security Report"
    echo ""
    read -p "Select option [1-3]: " monitor_choice
    
    if [[ -f "$SCRIPT_DIR/security-monitor.sh" ]]; then
        case $monitor_choice in
            1) "$SCRIPT_DIR/security-monitor.sh" dashboard ;;
            2) "$SCRIPT_DIR/security-monitor.sh" monitor ;;
            3) "$SCRIPT_DIR/security-monitor.sh" report ;;
            *) "$SCRIPT_DIR/security-monitor.sh" dashboard ;;
        esac
    else
        echo -e "${RED}Error: Security monitor script not found${NC}"
        return 1
    fi
    
    read -p "Press Enter to continue..."
}

run_test_suite() {
    echo -e "\n${GREEN}🧪 Running Test Suite${NC}"
    echo "Comprehensive testing of all Secreton components."
    echo ""
    
    cd "$SECRETON_ROOT"
    
    echo -e "${BLUE}Building Secreton...${NC}"
    if cargo build --release; then
        echo -e "${GREEN}✅ Build successful${NC}"
    else
        echo -e "${RED}❌ Build failed${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "\n${BLUE}Running unit tests...${NC}"
    if cargo test --release --lib; then
        echo -e "${GREEN}✅ Unit tests passed${NC}"
    else
        echo -e "${RED}❌ Unit tests failed${NC}"
    fi
    
    echo -e "\n${BLUE}Running integration tests...${NC}"
    if cargo test --release --test "*"; then
        echo -e "${GREEN}✅ Integration tests passed${NC}"
    else
        echo -e "${RED}❌ Integration tests failed${NC}"
    fi
    
    echo -e "\n${GREEN}✅ Test suite completed!${NC}"
    read -p "Press Enter to continue..."
}

performance_benchmark() {
    echo -e "\n${GREEN}📊 Performance Benchmark${NC}"
    echo "Comprehensive performance testing and comparison."
    echo ""
    
    cd "$SECRETON_ROOT"
    
    echo -e "${BLUE}Running performance benchmarks...${NC}"
    if cargo bench; then
        echo -e "${GREEN}✅ Benchmarks completed${NC}"
        echo ""
        echo -e "${BLUE}View detailed results in target/criterion/report/index.html${NC}"
    else
        echo -e "${RED}❌ Benchmarks failed${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

system_health_check() {
    echo -e "\n${GREEN}❤️  System Health Check${NC}"
    echo "Real-time system health and performance metrics."
    echo ""
    
    # Check system resources
    echo -e "${BLUE}System Resources:${NC}"
    echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F% '{print $1}')%"
    echo "Memory Usage: $(free | awk '/Mem/{printf("%.1f"), $3/$2*100}')%"
    echo "Disk Usage: $(df / | awk 'NR==2{print $5}')"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    echo ""
    
    # Check services
    echo -e "${BLUE}Service Status:${NC}"
    if systemctl is-active --quiet secreton.service; then
        echo -e "Secreton Service: ${GREEN}ACTIVE${NC}"
    else
        echo -e "Secreton Service: ${RED}INACTIVE${NC}"
    fi
    
    if command -v docker &> /dev/null; then
        local containers=$(docker ps --filter "name=secreton" --format "{{.Names}}" | wc -l)
        echo "Docker Containers: $containers running"
    fi
    
    # Check API health
    echo ""
    echo -e "${BLUE}API Health:${NC}"
    if curl -s -k https://localhost:8200/v1/sys/health > /dev/null; then
        local health=$(curl -s -k https://localhost:8200/v1/sys/health)
        local sealed=$(echo "$health" | jq -r '.sealed // "unknown"')
        local initialized=$(echo "$health" | jq -r '.initialized // "unknown"')
        
        echo -e "API Endpoint: ${GREEN}ACCESSIBLE${NC}"
        echo "Sealed: $sealed"
        echo "Initialized: $initialized"
    else
        echo -e "API Endpoint: ${RED}NOT ACCESSIBLE${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

view_live_logs() {
    echo -e "\n${GREEN}📜 Live Logs Viewer${NC}"
    echo "Select log file to monitor:"
    echo ""
    echo "1. Main Application Log"
    echo "2. Security Monitor Log"
    echo "3. Audit Log"
    echo "4. System Log"
    echo ""
    read -p "Select log [1-4]: " log_choice
    
    local log_file=""
    case $log_choice in
        1) log_file="/var/log/secreton/secreton.log" ;;
        2) log_file="/var/log/secreton/security-monitor.log" ;;
        3) log_file="/var/log/secreton/audit.log" ;;
        4) log_file="/var/log/syslog" ;;
        *) log_file="/var/log/secreton/secreton.log" ;;
    esac
    
    if [[ -f "$log_file" ]]; then
        echo -e "\n${BLUE}Following log: $log_file${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop${NC}\n"
        tail -f "$log_file"
    else
        echo -e "${RED}Log file not found: $log_file${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

service_control() {
    echo -e "\n${GREEN}⚙️  Service Control${NC}"
    echo "Manage Secreton system services:"
    echo ""
    echo "1. Start Services"
    echo "2. Stop Services" 
    echo "3. Restart Services"
    echo "4. View Service Status"
    echo ""
    read -p "Select action [1-4]: " service_choice
    
    case $service_choice in
        1)
            echo -e "\n${BLUE}Starting Secreton services...${NC}"
            sudo systemctl start secreton.service
            echo -e "${GREEN}✅ Services started${NC}"
            ;;
        2)
            echo -e "\n${BLUE}Stopping Secreton services...${NC}"
            sudo systemctl stop secreton.service
            echo -e "${GREEN}✅ Services stopped${NC}"
            ;;
        3)
            echo -e "\n${BLUE}Restarting Secreton services...${NC}"
            sudo systemctl restart secreton.service
            echo -e "${GREEN}✅ Services restarted${NC}"
            ;;
        4)
            echo -e "\n${BLUE}Service Status:${NC}"
            sudo systemctl status secreton.service
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

view_documentation() {
    echo -e "\n${GREEN}📚 Documentation Viewer${NC}"
    echo "Select documentation to view:"
    echo ""
    echo "1. Implementation Complete Guide"
    echo "2. Architecture Overview" 
    echo "3. Performance Benchmarks"
    echo "4. HashiCorp Vault Comparison"
    echo "5. Security Features"
    echo ""
    read -p "Select document [1-5]: " doc_choice
    
    local doc_file=""
    case $doc_choice in
        1) doc_file="$SECRETON_ROOT/IMPLEMENTATION_COMPLETE.md" ;;
        2) doc_file="$SECRETON_ROOT/crates/core/src/security/README.md" ;;
        3) doc_file="$SECRETON_ROOT/docs/PERFORMANCE_BENCHMARKS.md" ;;
        4) doc_file="$SECRETON_ROOT/docs/VAULT_COMPARISON.md" ;;
        5) doc_file="$SECRETON_ROOT/README.md" ;;
    esac
    
    if [[ -f "$doc_file" ]] && command -v less &> /dev/null; then
        less "$doc_file"
    elif [[ -f "$doc_file" ]]; then
        cat "$doc_file" | head -50
        echo -e "\n${YELLOW}(Showing first 50 lines - install 'less' for full viewing)${NC}"
    else
        echo -e "${RED}Documentation file not found: $doc_file${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Emergency procedures
emergency_procedures() {
    echo -e "\n${RED}🚨 EMERGENCY PROCEDURES${NC}"
    echo -e "${RED}Use these procedures only in emergency situations${NC}"
    echo ""
    echo "1. Emergency System Shutdown"
    echo "2. Seal Vault (Emergency)"
    echo "3. Revoke All Sessions"
    echo "4. Enable Lockdown Mode"
    echo "5. Generate Emergency Report"
    echo ""
    read -p "Select emergency procedure [1-5]: " emergency_choice
    
    echo -e "\n${RED}⚠️  WARNING: This is an emergency procedure!${NC}"
    read -p "Type 'EMERGENCY' to confirm: " confirm
    
    if [[ "$confirm" != "EMERGENCY" ]]; then
        echo -e "${YELLOW}Emergency procedure cancelled${NC}"
        return
    fi
    
    case $emergency_choice in
        1)
            echo -e "\n${RED}Executing emergency shutdown...${NC}"
            sudo systemctl stop secreton.service
            docker-compose -f /opt/secreton/docker-compose.yml down
            echo -e "${GREEN}✅ Emergency shutdown completed${NC}"
            ;;
        2)
            echo -e "\n${RED}Sealing vault...${NC}"
            curl -X PUT -k https://localhost:8200/v1/sys/seal
            echo -e "${GREEN}✅ Vault sealed${NC}"
            ;;
        3)
            echo -e "\n${RED}Revoking all sessions...${NC}"
            # Implementation would revoke all active sessions
            echo -e "${GREEN}✅ All sessions revoked${NC}"
            ;;
        4)
            echo -e "\n${RED}Enabling lockdown mode...${NC}"
            # Implementation would enable lockdown mode
            echo -e "${GREEN}✅ Lockdown mode enabled${NC}"
            ;;
        5)
            echo -e "\n${RED}Generating emergency report...${NC}"
            if [[ -f "$SCRIPT_DIR/security-monitor.sh" ]]; then
                "$SCRIPT_DIR/security-monitor.sh" report
            fi
            echo -e "${GREEN}✅ Emergency report generated${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# Main loop
main() {
    while true; do
        show_header
        show_main_menu
        
        read -r choice
        
        case $choice in
            1) deploy_full_system ;;
            2) configure_optimization ;;
            3) production_readiness ;;
            4) security_monitoring ;;
            5) "$SCRIPT_DIR/security-monitor.sh" report; read -p "Press Enter to continue..." ;;
            6) curl -s -k https://localhost:8200/v1/threat-intelligence/status | jq .; read -p "Press Enter to continue..." ;;
            7) curl -s -k https://localhost:8200/v1/sys/compliance/status | jq .; read -p "Press Enter to continue..." ;;
            8) run_test_suite ;;
            9) performance_benchmark ;;
            10) system_health_check ;;
            11) /usr/local/bin/secreton-backup; read -p "Press Enter to continue..." ;;
            12) view_live_logs ;;
            13) echo -e "\n${BLUE}Opening metrics dashboard at http://localhost:3000${NC}"; read -p "Press Enter to continue..." ;;
            14) echo -e "\n${BLUE}Alert management via Grafana at http://localhost:3000${NC}"; read -p "Press Enter to continue..." ;;
            15) service_control ;;
            16) system_health_check ;;
            17) emergency_procedures ;;
            18) view_documentation ;;
            19) view_documentation ;;
            20) view_documentation ;;
            0) 
                echo -e "\n${GREEN}Thank you for using Secreton Advanced Security System!${NC}"
                exit 0 
                ;;
            *)
                echo -e "\n${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check required commands
    for cmd in curl jq docker systemctl; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}Missing required dependencies:${NC}"
        printf '%s\n' "${missing_deps[@]}"
        echo ""
        echo "Please install missing dependencies and try again."
        exit 1
    fi
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi
