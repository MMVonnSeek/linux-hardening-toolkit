#!/usr/bin/env bash
# =============================================================================
# linux-hardening-toolkit — hardening.sh
# Aplicação de correções de segurança para Ubuntu/Debian
# Autor: Professor Max — github.com/MMVonnSeek
# Uso: sudo bash hardening.sh [--interactive|--auto] [--category CAT] [--dry-run]
# =============================================================================

set -euo pipefail

TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$TOOLKIT_DIR/backups/$TIMESTAMP"
LOG_FILE="$TOOLKIT_DIR/logs/hardening_$TIMESTAMP.log"
MODE="interactive"
CATEGORY="all"
DRY_RUN=false
CHANGES=0

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
Uso: sudo bash hardening.sh [OPÇÕES]

Opções:
  --interactive    Confirma cada alteração antes de aplicar (padrão)
  --auto           Aplica todas as correções sem confirmação
  --dry-run        Mostra o que seria feito sem executar
  --category CAT   Categoria: all, ssh, users, network, audit, permissions
  -h, --help       Exibe esta ajuda

Exemplos:
  sudo bash hardening.sh --interactive
  sudo bash hardening.sh --auto --category ssh
  sudo bash hardening.sh --dry-run
EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERRO]${NC} Este script requer privilégios root."
        echo "Execute: sudo bash hardening.sh"
        exit 1
    fi
}

log_action() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$LOG_FILE"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak"
        log_action "Backup criado: $file -> $BACKUP_DIR/"
    fi
}

apply_fix() {
    local description="$1"
    local command="$2"

    if [[ "$DRY_RUN" == true ]]; then
        echo -e "  ${BLUE}[DRY-RUN]${NC} $description"
        echo -e "           Comando: $command"
        return
    fi

    if [[ "$MODE" == "interactive" ]]; then
        echo -e "\n  ${YELLOW}[AÇÃO]${NC} $description"
        echo -e "  Comando: ${BOLD}$command${NC}"
        read -rp "  Aplicar? (s/N): " confirm
        [[ "$confirm" != "s" && "$confirm" != "S" ]] && \
            echo -e "  ${YELLOW}[PULADO]${NC}" && return
    else
        echo -e "  ${GREEN}[APLICANDO]${NC} $description"
    fi

    eval "$command"
    CHANGES=$((CHANGES + 1))
    log_action "APLICADO: $description | Comando: $command"
    echo -e "  ${GREEN}[OK]${NC}"
}

# =============================================================================
# Correções por categoria
# =============================================================================

fix_ssh() {
    echo -e "\n${BOLD}[SSH]${NC}"
    local sshd_config="/etc/ssh/sshd_config"
    backup_file "$sshd_config"

    # PermitRootLogin
    local root_login
    root_login=$(sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
    if [[ "$root_login" != "no" ]]; then
        apply_fix \
            "Desabilitar login root via SSH" \
            "sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $sshd_config && \
             grep -q '^PermitRootLogin' $sshd_config || echo 'PermitRootLogin no' >> $sshd_config"
    else
        echo -e "  ${GREEN}[OK]${NC} PermitRootLogin já está desabilitado"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(sshd -T 2>/dev/null | grep "^maxauthtries" | awk '{print $2}')
    if [[ "$max_auth" -gt 3 ]]; then
        apply_fix \
            "Reduzir MaxAuthTries para 3" \
            "sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' $sshd_config && \
             grep -q '^MaxAuthTries' $sshd_config || echo 'MaxAuthTries 3' >> $sshd_config"
    else
        echo -e "  ${GREEN}[OK]${NC} MaxAuthTries já está configurado ($max_auth)"
    fi

    # X11Forwarding
    local x11
    x11=$(sshd -T 2>/dev/null | grep "^x11forwarding" | awk '{print $2}')
    if [[ "$x11" != "no" ]]; then
        apply_fix \
            "Desabilitar X11Forwarding" \
            "sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' $sshd_config && \
             grep -q '^X11Forwarding' $sshd_config || echo 'X11Forwarding no' >> $sshd_config"
    else
        echo -e "  ${GREEN}[OK]${NC} X11Forwarding já está desabilitado"
    fi

    # LoginGraceTime
    local grace
    grace=$(sshd -T 2>/dev/null | grep "^logingracetime" | awk '{print $2}')
    if [[ "$grace" -gt 30 ]]; then
        apply_fix \
            "Reduzir LoginGraceTime para 30 segundos" \
            "sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' $sshd_config && \
             grep -q '^LoginGraceTime' $sshd_config || echo 'LoginGraceTime 30' >> $sshd_config"
    else
        echo -e "  ${GREEN}[OK]${NC} LoginGraceTime já está configurado ($grace)"
    fi

    # Recarregar SSH após alterações
    if [[ "$DRY_RUN" == false && $CHANGES -gt 0 ]]; then
        if sshd -t; then
            apply_fix \
                "Recarregar configuração do SSH" \
                "systemctl reload sshd 2>/dev/null || systemctl reload ssh"
        else
            echo -e "  ${RED}[ERRO]${NC} Configuração SSH inválida — não recarregando"
            echo -e "  Verifique manualmente: sudo sshd -t"
        fi
    fi
}

fix_audit() {
    echo -e "\n${BOLD}[AUDITORIA E LOGS]${NC}"

    # Instalar e habilitar auditd
    if ! systemctl is-active auditd &>/dev/null; then
        apply_fix \
            "Instalar e habilitar auditd" \
            "apt-get install -y auditd audispd-plugins && systemctl enable --now auditd"
    else
        echo -e "  ${GREEN}[OK]${NC} auditd já está ativo"
    fi

    # Regras básicas de auditoria
    local rules_file="/etc/audit/rules.d/hardening.rules"
    if [[ ! -f "$rules_file" ]]; then
        apply_fix \
            "Criar regras de auditoria para arquivos críticos" \
            "cat > $rules_file << 'RULES'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /var/log/auth.log -p rwa -k auth_log
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-w /tmp -p x -k tmp_execution
-w /var/tmp -p x -k tmp_execution
-w /etc/cron.d/ -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification
RULES
augenrules --load 2>/dev/null || auditctl -R $rules_file"
    else
        echo -e "  ${GREEN}[OK]${NC} Regras de auditoria já existem em $rules_file"
    fi
}

fix_permissions() {
    echo -e "\n${BOLD}[PERMISSÕES]${NC}"

    # /etc/passwd
    local passwd_perms
    passwd_perms=$(stat -c "%a" /etc/passwd)
    if [[ "$passwd_perms" != "644" ]]; then
        apply_fix \
            "Corrigir permissões de /etc/passwd (644)" \
            "chmod 644 /etc/passwd"
    else
        echo -e "  ${GREEN}[OK]${NC} Permissões de /etc/passwd corretas"
    fi

    # /etc/shadow
    local shadow_perms
    shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "N/A")
    if [[ "$shadow_perms" != "640" && "$shadow_perms" != "000" ]]; then
        apply_fix \
            "Corrigir permissões de /etc/shadow (640)" \
            "chmod 640 /etc/shadow"
    else
        echo -e "  ${GREEN}[OK]${NC} Permissões de /etc/shadow corretas"
    fi

    # Sticky bit em /tmp
    local tmp_perms
    tmp_perms=$(stat -c "%a" /tmp)
    if [[ "$tmp_perms" != "1777" ]]; then
        apply_fix \
            "Configurar sticky bit em /tmp (1777)" \
            "chmod 1777 /tmp"
    else
        echo -e "  ${GREEN}[OK]${NC} Sticky bit em /tmp já configurado"
    fi
}

fix_network() {
    echo -e "\n${BOLD}[REDE]${NC}"

    # Instalar e habilitar ufw se não houver firewall
    if ! ufw status 2>/dev/null | grep -q "Status: active" && \
       ! systemctl is-active nftables &>/dev/null; then
        apply_fix \
            "Instalar e habilitar ufw" \
            "apt-get install -y ufw && \
             ufw default deny incoming && \
             ufw default allow outgoing && \
             ufw allow ssh && \
             ufw --force enable"
    else
        echo -e "  ${GREEN}[OK]${NC} Firewall já está ativo"
    fi

    # Desabilitar IP forwarding
    local ip_forward
    ip_forward=$(sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}')
    if [[ "$ip_forward" != "0" ]]; then
        apply_fix \
            "Desabilitar IP forwarding" \
            "sysctl -w net.ipv4.ip_forward=0 && \
             grep -q 'net.ipv4.ip_forward' /etc/sysctl.conf && \
             sed -i 's/net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf || \
             echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf"
    else
        echo -e "  ${GREEN}[OK]${NC} IP forwarding já está desabilitado"
    fi
}

fix_users() {
    echo -e "\n${BOLD}[USUÁRIOS]${NC}"

    # Instalar pam_pwquality
    if ! dpkg -l libpam-pwquality &>/dev/null 2>&1; then
        apply_fix \
            "Instalar libpam-pwquality para política de senhas" \
            "apt-get install -y libpam-pwquality"
    else
        echo -e "  ${GREEN}[OK]${NC} libpam-pwquality já está instalado"
    fi

    # Instalar fail2ban
    if ! systemctl is-active fail2ban &>/dev/null; then
        apply_fix \
            "Instalar e configurar fail2ban" \
            "apt-get install -y fail2ban && \
             cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
maxretry = 3
bantime  = 86400
F2B
systemctl enable --now fail2ban"
    else
        echo -e "  ${GREEN}[OK]${NC} fail2ban já está ativo"
    fi
}

# =============================================================================
# Execução principal
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interactive) MODE="interactive"; shift ;;
        --auto)        MODE="auto"; shift ;;
        --dry-run)     DRY_RUN=true; shift ;;
        --category)    CATEGORY="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Opção desconhecida: $1"; usage; exit 1 ;;
    esac
done

check_root
mkdir -p "$TOOLKIT_DIR/logs"

echo -e "${BOLD}"
echo "============================================================"
echo "  Linux Hardening Toolkit — Aplicação de Correções"
echo "  Host: $(hostname) | $(date)"
[[ "$DRY_RUN" == true ]] && echo "  MODO: DRY-RUN (nenhuma alteração será feita)"
[[ "$MODE" == "auto" ]]  && echo "  MODO: AUTOMÁTICO"
[[ "$MODE" == "interactive" ]] && echo "  MODO: INTERATIVO"
echo "============================================================${NC}"

if [[ "$MODE" == "auto" && "$DRY_RUN" == false ]]; then
    echo -e "\n${RED}[ATENÇÃO]${NC} Modo automático aplicará todas as correções sem confirmação."
    read -rp "Confirmar? (s/N): " confirm
    [[ "$confirm" != "s" && "$confirm" != "S" ]] && exit 0
fi

case "$CATEGORY" in
    all)
        fix_ssh
        fix_audit
        fix_permissions
        fix_network
        fix_users
        ;;
    ssh)         fix_ssh ;;
    audit)       fix_audit ;;
    permissions) fix_permissions ;;
    network)     fix_network ;;
    users)       fix_users ;;
    *)
        echo "Categoria desconhecida: $CATEGORY"
        exit 1
        ;;
esac

echo -e "\n${BOLD}============================================================"
echo "  CONCLUÍDO"
echo "============================================================${NC}"

if [[ "$DRY_RUN" == true ]]; then
    echo -e "  Modo dry-run — nenhuma alteração foi realizada."
else
    echo -e "  Alterações aplicadas: ${GREEN}$CHANGES${NC}"
    [[ $CHANGES -gt 0 ]] && echo -e "  Backups salvos em: $BACKUP_DIR"
    [[ $CHANGES -gt 0 ]] && echo -e "  Log salvo em: $LOG_FILE"
    echo -e "\n  Execute 'sudo bash audit.sh' para verificar o novo score."
fi

echo ""
