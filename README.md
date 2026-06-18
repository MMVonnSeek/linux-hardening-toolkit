[![Professor Max](https://img.shields.io/badge/Material_do_Professor_Max-Oficial-darkred?style=for-the-badge&logo=google-scholar&logoColor=white)](https://github.com/MMVonnSeek/linux-hardening-toolkit)
[![Repositório Original](https://img.shields.io/badge/Repositório-Original-black?style=for-the-badge&logo=github)](https://github.com/MMVonnSeek/linux-hardening-toolkit)
[![Linux](https://img.shields.io/badge/Ubuntu-Debian-darkred?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/MMVonnSeek/linux-hardening-toolkit)
[![Licença](https://img.shields.io/badge/Licença-MIT-black?style=for-the-badge)](LICENSE)
[![Sponsor](https://img.shields.io/badge/_Apoie_este_projeto-Sponsor-ea4aaa?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/MMVonnSeek)

---

<div align="center">

# Linux Hardening Toolkit

**Auditoria e hardening automatizado de servidores Linux baseado no CIS Benchmark.**

*Detecta, relata e corrige configurações inseguras em servidores Ubuntu/Debian.*

</div>

---

## O problema que este projeto resolve

Configurar um servidor Linux seguro do zero leva horas e exige conhecimento profundo de dezenas de parâmetros. Empresas pequenas não têm budget para ferramentas comerciais como Tenable ou Qualys. Administradores experientes perdem tempo verificando manualmente o mesmo checklist toda vez que provisionam um servidor novo.

Este toolkit automatiza esse processo: audita o estado atual, gera um relatório com score de segurança e aplica as correções de forma interativa ou automatizada.

---

## Demonstração rápida

```bash
# Clonar o repositório
git clone https://github.com/MMVonnSeek/linux-hardening-toolkit.git
cd linux-hardening-toolkit

# Executar auditoria (não faz nenhuma alteração)
sudo bash audit.sh

# Relatório gerado em reports/audit_YYYYMMDD_HHMMSS.html
# Abrir no navegador
xdg-open reports/audit_*.html
```

---

## Funcionalidades

**audit.sh — auditoria completa sem alterações**
- Verifica mais de 40 controles de segurança baseados no CIS Benchmark
- Gera relatório HTML com score geral (0–100)
- Exporta resultados em JSON para integração com SIEM
- Não modifica nada no sistema — seguro para rodar em produção

**hardening.sh — aplicação de correções**
- Modo interativo: confirma cada alteração antes de aplicar
- Modo automático: aplica todas as correções de uma vez
- Cria backup automático de cada arquivo modificado
- Log completo de todas as alterações realizadas

**report.py — gerador de relatório**
- Relatório HTML com score visual antes/depois
- Tabela de verificações com status, risco e comando de correção
- Exportação em HTML, JSON e texto simples

---

## Controles verificados

### Configuração do sistema
- [ ] Partições separadas para `/tmp`, `/var`, `/home`
- [ ] `/tmp` montado com `noexec`, `nosuid`, `nodev`
- [ ] Atualizações automáticas de segurança configuradas
- [ ] Pacotes desnecessários removidos

### Usuários e autenticação
- [ ] Política de senha configurada via PAM
- [ ] Bloqueio de conta após tentativas falhas
- [ ] Contas sem senha identificadas
- [ ] Usuários com UID 0 além de root
- [ ] Contas de serviço com shell `/usr/sbin/nologin`

### SSH
- [ ] `PermitRootLogin no`
- [ ] `PasswordAuthentication no`
- [ ] `MaxAuthTries 3` ou menor
- [ ] Algoritmos criptográficos modernos
- [ ] Porta padrão alterada

### Rede e firewall
- [ ] firewall ativo (ufw ou nftables)
- [ ] Portas abertas mapeadas e justificadas
- [ ] Serviços internos não expostos externamente
- [ ] IPv6 desabilitado se não utilizado

### Auditoria e logs
- [ ] `auditd` instalado e ativo
- [ ] Regras de auditoria para arquivos críticos
- [ ] Retenção de logs configurada
- [ ] `rsyslog` ativo

### Permissões
- [ ] Arquivos SUID/SGID mapeados
- [ ] Arquivos world-writable fora de `/tmp`
- [ ] Permissões corretas em `/etc/passwd`, `/etc/shadow`
- [ ] Diretórios home com permissão `750` ou mais restrita

---

## Estrutura do repositório

```
linux-hardening-toolkit/
├── audit.sh              - script de auditoria (leitura apenas)
├── hardening.sh          - script de aplicação de correções
├── report.py             - gerador de relatório HTML/JSON
├── profiles/
│   ├── server-web.sh     - perfil para servidores web (nginx/apache)
│   ├── server-db.sh      - perfil para servidores de banco de dados
│   └── workstation.sh    - perfil para estações de trabalho
├── lib/
│   ├── checks.sh         - funções de verificação
│   ├── fixes.sh          - funções de correção
│   └── report.sh         - funções de geração de relatório
├── reports/              - relatórios gerados (ignorado pelo git)
├── docs/
│   └── checks.md         - documentação de cada verificação
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

## Pré-requisitos

- Ubuntu 20.04+ ou Debian 11+
- Bash 5.0+
- Python 3.8+ (para geração de relatório HTML)
- Acesso sudo

```bash
# Verificar pré-requisitos
bash --version
python3 --version
sudo -v
```

---

## Uso detalhado

### Auditoria completa

```bash
# Auditoria com relatório HTML
sudo bash audit.sh --report html

# Auditoria com relatório JSON (para integração com outras ferramentas)
sudo bash audit.sh --report json

# Auditoria de categoria específica
sudo bash audit.sh --category ssh
sudo bash audit.sh --category users
sudo bash audit.sh --category network

# Auditoria silenciosa (apenas score final)
sudo bash audit.sh --quiet
```

### Aplicando hardening

```bash
# Modo interativo (recomendado para primeiro uso)
sudo bash hardening.sh --interactive

# Modo automático (para automação/CI)
sudo bash hardening.sh --auto

# Aplicar apenas categoria específica
sudo bash hardening.sh --category ssh

# Dry run (mostra o que seria feito sem executar)
sudo bash hardening.sh --dry-run
```

### Usando perfis

```bash
# Perfil para servidor web
sudo bash hardening.sh --profile server-web

# Perfil para banco de dados
sudo bash hardening.sh --profile server-db
```

---

## Interpretando o relatório

O relatório classifica cada verificação em três níveis:

| Status | Significado |
|--------|-------------|
| PASSOU | Controle está configurado corretamente |
| FALHOU | Controle não está implementado — requer ação |
| AVISO | Configuração presente mas pode ser melhorada |

O score é calculado como:

```
score = (verificações_passou / total_verificações) * 100
```

Referência de score:

| Score | Classificação |
|-------|--------------|
| 0–49 | Crítico — servidor exposto |
| 50–69 | Insuficiente — melhorias urgentes necessárias |
| 70–84 | Adequado — boa base, alguns gaps |
| 85–94 | Bom — configuração sólida |
| 95–100 | Excelente — alinhado com CIS Benchmark |

---

## Relação com linux-security-guide

Este toolkit implementa na prática os conceitos documentados no [linux-security-guide](https://github.com/MMVonnSeek/linux-security-guide). Para entender o que cada verificação faz e por que é importante, consulte o guia correspondente:

| Categoria do toolkit | Módulo do guia |
|---------------------|----------------|
| Usuários e autenticação | [Usuários e Grupos](https://github.com/MMVonnSeek/linux-security-guide/blob/main/01-fundamentos/usuarios-grupos.md) |
| SSH | [SSH Seguro](https://github.com/MMVonnSeek/linux-security-guide/blob/main/03-hardening/ssh-seguro.md) |
| Auditoria e logs | [Auditoria de Logs](https://github.com/MMVonnSeek/linux-security-guide/blob/main/03-hardening/auditoria-logs.md) |
| Permissões | [Permissões no Linux](https://github.com/MMVonnSeek/linux-security-guide/blob/main/01-fundamentos/permissoes.md) |

---

## Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para padrões de contribuição.

Novos controles são bem-vindos. Cada controle precisa de:
- Função de verificação em `lib/checks.sh`
- Função de correção em `lib/fixes.sh`
- Documentação em `docs/checks.md`
- Referência ao CIS Benchmark correspondente

---

<div align="center">

[![Professor Max](https://img.shields.io/badge/Material_do_Professor_Max-Oficial-black?style=for-the-badge&logo=google-scholar&logoColor=white)](https://github.com/MMVonnSeek/linux-security-guide)
[![Sponsor](https://img.shields.io/badge/Apoie_este_projeto-Sponsor-ea4aaa?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/MMVonnSeek)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Max_Muller-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/max-muller-685705248/)

*Feito com ☕ e muito terminal por Professor Max*

</div>
