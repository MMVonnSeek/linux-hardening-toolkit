#!/usr/bin/env bash
# =============================================================================
# linux-hardening-toolkit — audit.sh
# Auditoria de segurança para Ubuntu/Debian baseada no CIS Benchmark
# Autor: Professor Max — github.com/MMVonnSeek
# Uso: sudo bash audit.sh [--report html|json|text] [--category CATEGORIA] [--quiet]
# =============================================================================

set -euo pipefail

# --- Configuração ---
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$TOOLKIT_DIR/lib"
REPORTS_DIR="$TOOLKIT_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORTS_DIR/audit_$TIMESTAMP"
REPORT_FORMAT="html"
CATEGORY="all"
QUIET=false

# Contadores
TOTAL=0
PASSED=0
FAILED=0
WARNED=0

# Arrays de resultados
declare -a RESULTS=()

# --- Cores ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Funções utilitárias
# =============================================================================

usage() {
    cat << EOF
Uso: sudo bash audit.sh [OPÇÕES]

Opções:
  --report FORMAT     Formato do relatório: html (padrão), json, text
  --category CAT      Categoria: all, system, users, ssh, network, audit, permissions
  --quiet             Exibe apenas o score final
  -h, --help          Exibe esta ajuda

Exemplos:
  sudo bash audit.sh
  sudo bash audit.sh --report json
  sudo bash audit.sh --category ssh
  sudo bash audit.sh --quiet
EOF
}

log() {
    [[ "$QUIET" == false ]] && echo -e "$1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERRO]${NC} Este script requer privilégios root."
        echo "Execute: sudo bash audit.sh"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/debian_version ]]; then
        echo -e "${YELLOW}[AVISO]${NC} Este toolkit foi desenvolvido para Ubuntu/Debian."
        echo "Alguns controles podem não funcionar corretamente nesta distribuição."
        read -rp "Continuar mesmo assim? (s/N): " confirm
        [[ "$confirm" != "s" && "$confirm" != "S" ]] && exit 0
    fi
}

mkdir -p "$REPORTS_DIR"

# =============================================================================
# Funções de verificação
# =============================================================================

# Registra resultado de uma verificação
# Uso: record_check "ID" "DESCRIÇÃO" "STATUS" "DETALHE" "CORREÇÃO"
record_check() {
    local id="$1"
    local description="$2"
    local status="$3"    # PASSED | FAILED | WARN
    local detail="$4"
    local fix="$5"

    TOTAL=$((TOTAL + 1))

    case "$status" in
        PASSED) PASSED=$((PASSED + 1)) ;;
        FAILED) FAILED=$((FAILED + 1)) ;;
        WARN)   WARNED=$((WARNED + 1)) ;;
    esac

    RESULTS+=("$id|$description|$status|$detail|$fix")

    if [[ "$QUIET" == false ]]; then
        case "$status" in
            PASSED) echo -e "  ${GREEN}[PASSOU]${NC} $description" ;;
            FAILED) echo -e "  ${RED}[FALHOU]${NC} $description" ;;
            WARN)   echo -e "  ${YELLOW}[AVISO ]${NC} $description" ;;
        esac
    fi
}

# =============================================================================
# Categoria: Sistema
# =============================================================================

check_system() {
    log "\n${BOLD}[SISTEMA]${NC}"

    # Verificar atualizações pendentes de segurança
    local pending
    pending=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || true)
    if [[ "$pending" -eq 0 ]]; then
        record_check "SYS-01" "Sem atualizações de segurança pendentes" \
            "PASSED" "Sistema atualizado" ""
    else
        record_check "SYS-01" "Atualizações de segurança pendentes" \
            "FAILED" "$pending pacote(s) com atualização disponível" \
            "sudo apt-get upgrade -y"
    fi

    # Verificar atualizações automáticas
    if dpkg -l unattended-upgrades &>/dev/null && \
       [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        local auto_update
        auto_update=$(grep -c 'APT::Periodic::Unattended-Upgrade "1"' \
            /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || true)
        if [[ "$auto_update" -gt 0 ]]; then
            record_check "SYS-02" "Atualizações automáticas de segurança ativas" \
                "PASSED" "unattended-upgrades configurado" ""
        else
            record_check "SYS-02" "Atualizações automáticas de segurança inativas" \
                "WARN" "Pacote instalado mas não configurado" \
                "sudo dpkg-reconfigure unattended-upgrades"
        fi
    else
        record_check "SYS-02" "Atualizações automáticas de segurança não configuradas" \
            "FAILED" "unattended-upgrades não instalado ou não configurado" \
            "sudo apt-get install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades"
    fi

    # Verificar /tmp com noexec
    if mount | grep -E '\s/tmp\s' | grep -q noexec; then
        record_check "SYS-03" "/tmp montado com noexec" \
            "PASSED" "Opção noexec presente" ""
    else
        record_check "SYS-03" "/tmp sem opção noexec" \
            "FAILED" "Execução de binários permitida em /tmp" \
            "Adicionar 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0' em /etc/fstab"
    fi

    # Verificar /tmp com nosuid
    if mount | grep -E '\s/tmp\s' | grep -q nosuid; then
        record_check "SYS-04" "/tmp montado com nosuid" \
            "PASSED" "Opção nosuid presente" ""
    else
        record_check "SYS-04" "/tmp sem opção nosuid" \
            "FAILED" "SUID bits podem ser explorados em /tmp" \
            "Adicionar nosuid às opções de montagem do /tmp em /etc/fstab"
    fi

    # Verificar se core dumps estão desabilitados
    local core_limit
    core_limit=$(ulimit -c 2>/dev/null || echo "unlimited")
    if grep -qE '^\*.*hard.*core.*0' /etc/security/limits.conf 2>/dev/null || \
       grep -qE 'fs.suid_dumpable\s*=\s*0' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
        record_check "SYS-05" "Core dumps desabilitados" \
            "PASSED" "Configuração restritiva presente" ""
    else
        record_check "SYS-05" "Core dumps não restringidos" \
            "WARN" "Core dumps podem expor dados sensíveis da memória" \
            "echo '* hard core 0' >> /etc/security/limits.conf && echo 'fs.suid_dumpable=0' >> /etc/sysctl.conf"
    fi
}

# =============================================================================
# Categoria: Usuários
# =============================================================================

check_users() {
    log "\n${BOLD}[USUÁRIOS E AUTENTICAÇÃO]${NC}"

    # Usuários com UID 0 além de root
    local uid0_users
    uid0_users=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [[ -z "$uid0_users" ]]; then
        record_check "USR-01" "Nenhum usuário extra com UID 0" \
            "PASSED" "Apenas root tem UID 0" ""
    else
        record_check "USR-01" "Usuários com UID 0 além de root detectados" \
            "FAILED" "Usuários: $uid0_users" \
            "Investigar e remover: sudo userdel <usuario>"
    fi

    # Contas sem senha
    local no_passwd
    no_passwd=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -z "$no_passwd" ]]; then
        record_check "USR-02" "Nenhuma conta sem senha" \
            "PASSED" "Todas as contas têm senha definida" ""
    else
        record_check "USR-02" "Contas sem senha detectadas" \
            "FAILED" "Contas: $no_passwd" \
            "sudo passwd -l <usuario> para bloquear ou sudo passwd <usuario> para definir senha"
    fi

    # Verificar algoritmo de hash de senhas
    local md5_users
    md5_users=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -z "$md5_users" ]]; then
        record_check "USR-03" "Nenhuma senha usando MD5 (algoritmo fraco)" \
            "PASSED" "Algoritmos de hash modernos em uso" ""
    else
        record_check "USR-03" "Senhas com hash MD5 detectadas" \
            "FAILED" "Usuários: $md5_users" \
            "Forçar troca de senha: sudo chage -d 0 <usuario>"
    fi

    # Política de senha — pam_pwquality
    if dpkg -l libpam-pwquality &>/dev/null 2>&1; then
        record_check "USR-04" "pam_pwquality instalado" \
            "PASSED" "Módulo de qualidade de senha presente" ""
    else
        record_check "USR-04" "pam_pwquality não instalado" \
            "FAILED" "Sem política de complexidade de senha" \
            "sudo apt-get install libpam-pwquality"
    fi

    # Verificar faillock / pam_tally2
    if grep -qE 'pam_faillock|pam_tally2' /etc/pam.d/common-auth 2>/dev/null; then
        record_check "USR-05" "Bloqueio de conta por tentativas falhas configurado" \
            "PASSED" "pam_faillock ou pam_tally2 presente em common-auth" ""
    else
        record_check "USR-05" "Bloqueio de conta por tentativas falhas não configurado" \
            "WARN" "Sem proteção contra força bruta local" \
            "Configurar pam_faillock em /etc/pam.d/common-auth"
    fi

    # Verificar contas com shell válido
    local shell_users
    shell_users=$(grep -v '/nologin\|/false\|/sync' /etc/passwd | \
        awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | tr '\n' ' ')
    log "  ${BLUE}[INFO ]${NC} Usuários com shell de login: $shell_users"
}

# =============================================================================
# Categoria: SSH
# =============================================================================

check_ssh() {
    log "\n${BOLD}[SSH]${NC}"

    if ! systemctl is-active sshd &>/dev/null && ! systemctl is-active ssh &>/dev/null; then
        log "  ${BLUE}[INFO ]${NC} SSH não está em execução — pulando verificações SSH"
        return
    fi

    local sshd_config="/etc/ssh/sshd_config"

    # PermitRootLogin
    local root_login
    root_login=$(sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
    if [[ "$root_login" == "no" ]]; then
        record_check "SSH-01" "PermitRootLogin desabilitado" \
            "PASSED" "root não pode fazer login via SSH" ""
    else
        record_check "SSH-01" "PermitRootLogin habilitado" \
            "FAILED" "Valor atual: $root_login" \
            "Definir 'PermitRootLogin no' em $sshd_config"
    fi

    # PasswordAuthentication
    local passwd_auth
    passwd_auth=$(sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
    if [[ "$passwd_auth" == "no" ]]; then
        record_check "SSH-02" "Autenticação por senha desabilitada" \
            "PASSED" "Apenas chave pública permitida" ""
    else
        record_check "SSH-02" "Autenticação por senha habilitada" \
            "WARN" "Vulnerável a força bruta se fail2ban não estiver ativo" \
            "Definir 'PasswordAuthentication no' em $sshd_config (após configurar chaves)"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(sshd -T 2>/dev/null | grep "^maxauthtries" | awk '{print $2}')
    if [[ "$max_auth" -le 3 ]]; then
        record_check "SSH-03" "MaxAuthTries configurado ($max_auth)" \
            "PASSED" "Máximo de $max_auth tentativas por conexão" ""
    else
        record_check "SSH-03" "MaxAuthTries muito alto ($max_auth)" \
            "FAILED" "Permite muitas tentativas antes de desconectar" \
            "Definir 'MaxAuthTries 3' em $sshd_config"
    fi

    # X11Forwarding
    local x11
    x11=$(sshd -T 2>/dev/null | grep "^x11forwarding" | awk '{print $2}')
    if [[ "$x11" == "no" ]]; then
        record_check "SSH-04" "X11Forwarding desabilitado" \
            "PASSED" "Vetor de ataque via X11 eliminado" ""
    else
        record_check "SSH-04" "X11Forwarding habilitado" \
            "WARN" "Vetor de ataque desnecessário se GUI não for usada" \
            "Definir 'X11Forwarding no' em $sshd_config"
    fi

    # LoginGraceTime
    local grace
    grace=$(sshd -T 2>/dev/null | grep "^logingracetime" | awk '{print $2}')
    if [[ "$grace" -le 30 ]]; then
        record_check "SSH-05" "LoginGraceTime configurado ($grace segundos)" \
            "PASSED" "Tempo de autenticação limitado" ""
    else
        record_check "SSH-06" "LoginGraceTime muito alto ($grace segundos)" \
            "WARN" "Janela longa para ataques de autenticação" \
            "Definir 'LoginGraceTime 30' em $sshd_config"
    fi

    # fail2ban para SSH
    if systemctl is-active fail2ban &>/dev/null; then
        record_check "SSH-06" "fail2ban ativo" \
            "PASSED" "Proteção contra força bruta em execução" ""
    else
        record_check "SSH-06" "fail2ban não está ativo" \
            "FAILED" "Sem proteção automática contra força bruta" \
            "sudo apt-get install fail2ban && sudo systemctl enable --now fail2ban"
    fi
}

# =============================================================================
# Categoria: Rede
# =============================================================================

check_network() {
    log "\n${BOLD}[REDE E FIREWALL]${NC}"

    # Verificar firewall ativo (ufw ou nftables)
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        record_check "NET-01" "ufw ativo" \
            "PASSED" "Firewall em execução" ""
    elif systemctl is-active nftables &>/dev/null; then
        record_check "NET-01" "nftables ativo" \
            "PASSED" "Firewall em execução" ""
    else
        record_check "NET-01" "Nenhum firewall ativo detectado" \
            "FAILED" "ufw e nftables inativos" \
            "sudo apt-get install ufw && sudo ufw enable"
    fi

    # Verificar serviços escutando em 0.0.0.0 desnecessariamente
    local exposed_services
    exposed_services=$(ss -tlnp 2>/dev/null | grep "0.0.0.0" | \
        grep -vE ':22|:80|:443' | wc -l)
    if [[ "$exposed_services" -eq 0 ]]; then
        record_check "NET-02" "Nenhum serviço interno exposto externamente" \
            "PASSED" "Serviços internos restritos ao loopback" ""
    else
        record_check "NET-02" "Serviços possivelmente expostos desnecessariamente" \
            "WARN" "$exposed_services serviço(s) escutando em 0.0.0.0 (exceto 22/80/443)" \
            "Verificar com 'ss -tlnp' e restringir serviços internos ao 127.0.0.1"
    fi

    # IPv6 desabilitado se não necessário
    if sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "= 1"; then
        record_check "NET-03" "IPv6 desabilitado" \
            "PASSED" "Superfície de ataque reduzida" ""
    else
        record_check "NET-03" "IPv6 habilitado" \
            "WARN" "Se IPv6 não é usado, pode ser desabilitado" \
            "echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf && sysctl -p"
    fi

    # Verificar IP forwarding
    local ip_forward
    ip_forward=$(sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}')
    if [[ "$ip_forward" == "0" ]]; then
        record_check "NET-04" "IP forwarding desabilitado" \
            "PASSED" "Servidor não atua como roteador" ""
    else
        record_check "NET-04" "IP forwarding habilitado" \
            "WARN" "Necessário apenas em gateways/roteadores" \
            "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf && sysctl -p"
    fi
}

# =============================================================================
# Categoria: Auditoria e Logs
# =============================================================================

check_audit() {
    log "\n${BOLD}[AUDITORIA E LOGS]${NC}"

    # auditd instalado e ativo
    if systemctl is-active auditd &>/dev/null; then
        record_check "AUD-01" "auditd instalado e ativo" \
            "PASSED" "Sistema de auditoria em execução" ""
    else
        record_check "AUD-01" "auditd não está ativo" \
            "FAILED" "Sem auditoria de eventos do kernel" \
            "sudo apt-get install auditd && sudo systemctl enable --now auditd"
    fi

    # Regras de auditoria para arquivos críticos
    if auditctl -l 2>/dev/null | grep -q "/etc/passwd"; then
        record_check "AUD-02" "Regras de auditoria para /etc/passwd configuradas" \
            "PASSED" "Alterações em arquivos de identidade monitoradas" ""
    else
        record_check "AUD-02" "Sem regras de auditoria para arquivos críticos" \
            "FAILED" "Alterações em /etc/passwd, /etc/shadow não são registradas" \
            "Adicionar regras em /etc/audit/rules.d/hardening.rules"
    fi

    # rsyslog ativo
    if systemctl is-active rsyslog &>/dev/null; then
        record_check "AUD-03" "rsyslog ativo" \
            "PASSED" "Centralização de logs funcionando" ""
    else
        record_check "AUD-03" "rsyslog não está ativo" \
            "WARN" "Logs podem não estar sendo persistidos corretamente" \
            "sudo systemctl enable --now rsyslog"
    fi

    # Verificar retenção de logs
    if grep -rq "rotate" /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null; then
        record_check "AUD-04" "Rotação de logs configurada" \
            "PASSED" "logrotate presente e configurado" ""
    else
        record_check "AUD-04" "Rotação de logs não configurada" \
            "WARN" "Logs podem crescer sem limite" \
            "Verificar /etc/logrotate.conf"
    fi
}

# =============================================================================
# Categoria: Permissões
# =============================================================================

check_permissions() {
    log "\n${BOLD}[PERMISSÕES]${NC}"

    # Permissões de /etc/passwd
    local passwd_perms
    passwd_perms=$(stat -c "%a" /etc/passwd)
    if [[ "$passwd_perms" == "644" ]]; then
        record_check "PRM-01" "Permissões corretas em /etc/passwd (644)" \
            "PASSED" "" ""
    else
        record_check "PRM-01" "Permissões incorretas em /etc/passwd ($passwd_perms)" \
            "FAILED" "Esperado: 644" \
            "sudo chmod 644 /etc/passwd"
    fi

    # Permissões de /etc/shadow
    local shadow_perms
    shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "N/A")
    if [[ "$shadow_perms" == "640" || "$shadow_perms" == "000" ]]; then
        record_check "PRM-02" "Permissões corretas em /etc/shadow ($shadow_perms)" \
            "PASSED" "" ""
    else
        record_check "PRM-02" "Permissões incorretas em /etc/shadow ($shadow_perms)" \
            "FAILED" "Esperado: 640 ou 000" \
            "sudo chmod 640 /etc/shadow"
    fi

    # Arquivos world-writable fora de /tmp
    local ww_files
    ww_files=$(find / -perm -o+w -type f \
        -not -path "/proc/*" \
        -not -path "/tmp/*" \
        -not -path "/var/tmp/*" \
        -not -path "/sys/*" \
        -not -path "/dev/*" \
        2>/dev/null | wc -l)
    if [[ "$ww_files" -eq 0 ]]; then
        record_check "PRM-03" "Nenhum arquivo world-writable fora de /tmp" \
            "PASSED" "" ""
    else
        record_check "PRM-03" "Arquivos world-writable detectados fora de /tmp" \
            "FAILED" "$ww_files arquivo(s) encontrado(s)" \
            "find / -perm -o+w -type f -not -path '/proc/*' -not -path '/tmp/*' 2>/dev/null"
    fi

    # Arquivos SUID não esperados em /tmp
    local suid_tmp
    suid_tmp=$(find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | wc -l)
    if [[ "$suid_tmp" -eq 0 ]]; then
        record_check "PRM-04" "Nenhum arquivo SUID em diretórios temporários" \
            "PASSED" "" ""
    else
        record_check "PRM-04" "Arquivos SUID em diretórios temporários detectados" \
            "FAILED" "$suid_tmp arquivo(s) — indicador de comprometimento" \
            "find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null"
    fi

    # Sticky bit em /tmp
    local tmp_perms
    tmp_perms=$(stat -c "%a" /tmp)
    if [[ "$tmp_perms" == "1777" ]]; then
        record_check "PRM-05" "Sticky bit em /tmp configurado (1777)" \
            "PASSED" "" ""
    else
        record_check "PRM-05" "Sticky bit ausente em /tmp ($tmp_perms)" \
            "FAILED" "Usuários podem deletar arquivos de outros em /tmp" \
            "sudo chmod 1777 /tmp"
    fi
}

# =============================================================================
# Geração de relatório
# =============================================================================

calculate_score() {
    if [[ $TOTAL -eq 0 ]]; then
        echo 0
        return
    fi
    echo $(( (PASSED * 100) / TOTAL ))
}

score_label() {
    local score=$1
    if [[ $score -ge 95 ]]; then echo "Excelente"
    elif [[ $score -ge 85 ]]; then echo "Bom"
    elif [[ $score -ge 70 ]]; then echo "Adequado"
    elif [[ $score -ge 50 ]]; then echo "Insuficiente"
    else echo "Crítico"
    fi
}

generate_text_report() {
    local score
    score=$(calculate_score)
    local label
    label=$(score_label "$score")

    echo "============================================================"
    echo "RELATÓRIO DE AUDITORIA DE SEGURANÇA"
    echo "Host: $(hostname) | Data: $(date)"
    echo "============================================================"
    echo ""
    echo "SCORE: $score/100 — $label"
    echo "Verificações: $TOTAL total | $PASSED passou | $FAILED falhou | $WARNED aviso"
    echo ""
    echo "------------------------------------------------------------"

    for result in "${RESULTS[@]}"; do
        IFS='|' read -r id desc status detail fix <<< "$result"
        printf "%-8s %-10s %s\n" "$id" "[$status]" "$desc"
        [[ -n "$detail" ]] && printf "         Detalhe: %s\n" "$detail"
        [[ -n "$fix" && "$status" != "PASSED" ]] && printf "         Correção: %s\n" "$fix"
    done
}

generate_json_report() {
    local score
    score=$(calculate_score)

    echo "{"
    echo "  \"host\": \"$(hostname)\","
    echo "  \"date\": \"$(date -Iseconds)\","
    echo "  \"score\": $score,"
    echo "  \"summary\": {"
    echo "    \"total\": $TOTAL,"
    echo "    \"passed\": $PASSED,"
    echo "    \"failed\": $FAILED,"
    echo "    \"warned\": $WARNED"
    echo "  },"
    echo "  \"checks\": ["

    local first=true
    for result in "${RESULTS[@]}"; do
        IFS='|' read -r id desc status detail fix <<< "$result"
        [[ "$first" == false ]] && echo "    ,"
        echo "    {"
        echo "      \"id\": \"$id\","
        echo "      \"description\": \"$desc\","
        echo "      \"status\": \"$status\","
        echo "      \"detail\": \"$detail\","
        echo "      \"fix\": \"$fix\""
        echo -n "    }"
        first=false
    done

    echo ""
    echo "  ]"
    echo "}"
}

# =============================================================================
# Execução principal
# =============================================================================

# Processar argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --report)   REPORT_FORMAT="$2"; shift 2 ;;
        --category) CATEGORY="$2"; shift 2 ;;
        --quiet)    QUIET=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "Opção desconhecida: $1"; usage; exit 1 ;;
    esac
done

check_root
check_os

log "${BOLD}"
log "============================================================"
log "  Linux Hardening Toolkit — Auditoria de Segurança"
log "  Host: $(hostname) | $(date)"
log "============================================================${NC}"

# Executar verificações por categoria
case "$CATEGORY" in
    all)
        check_system
        check_users
        check_ssh
        check_network
        check_audit
        check_permissions
        ;;
    system)      check_system ;;
    users)       check_users ;;
    ssh)         check_ssh ;;
    network)     check_network ;;
    audit)       check_audit ;;
    permissions) check_permissions ;;
    *)
        echo "Categoria desconhecida: $CATEGORY"
        echo "Categorias válidas: all, system, users, ssh, network, audit, permissions"
        exit 1
        ;;
esac

# Score final
SCORE=$(calculate_score)
LABEL=$(score_label "$SCORE")

log "\n${BOLD}============================================================"
log "  RESULTADO FINAL"
log "============================================================${NC}"
log "  Score: ${BOLD}$SCORE/100${NC} — $LABEL"
log "  Total: $TOTAL | Passou: ${GREEN}$PASSED${NC} | Falhou: ${RED}$FAILED${NC} | Aviso: ${YELLOW}$WARNED${NC}"

# Salvar relatório
case "$REPORT_FORMAT" in
    html)
        python3 "$TOOLKIT_DIR/report.py" \
            --host "$(hostname)" \
            --score "$SCORE" \
            --total "$TOTAL" \
            --passed "$PASSED" \
            --failed "$FAILED" \
            --warned "$WARNED" \
            --results "$(printf '%s\n' "${RESULTS[@]}")" \
            --output "$REPORT_FILE.html" 2>/dev/null && \
        log "\n  Relatório HTML salvo em: ${BOLD}$REPORT_FILE.html${NC}" || \
        generate_text_report | tee "$REPORT_FILE.txt" > /dev/null
        ;;
    json)
        generate_json_report | tee "$REPORT_FILE.json" > /dev/null
        log "\n  Relatório JSON salvo em: ${BOLD}$REPORT_FILE.json${NC}"
        ;;
    text)
        generate_text_report | tee "$REPORT_FILE.txt" > /dev/null
        log "\n  Relatório texto salvo em: ${BOLD}$REPORT_FILE.txt${NC}"
        ;;
esac

log ""

# Exit code baseado no score
[[ $FAILED -eq 0 ]] && exit 0 || exit 1
