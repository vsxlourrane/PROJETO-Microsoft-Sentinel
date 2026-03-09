# Detecção de Password Spray com Microsoft Sentinel

![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110.003%20%7C%20T1078-red)
![KQL](https://img.shields.io/badge/Language-KQL-brightgreen)
![Status](https://img.shields.io/badge/Status-Concluído-success)

# Cenário
Um sistema de monitoramento detectou **847 tentativas de login falhas em 12 minutos** 
contra contas do Azure AD. Em seguida, **3 logins bem-sucedidos** originados de IPs 
na Romênia — país nunca visto nos logs da empresa.

**Missão:** Detectar, investigar, conter e documentar o ataque como Analista SOC N1.

---

# Objetivos do Projeto
- Detectar ataque de Password Spray via KQL no Microsoft Sentinel
- Identificar contas comprometidas por correlação de eventos
- Realizar IOC Enrichment dos IPs suspeitos
- Executar resposta ao incidente com contenção
- Documentar Incident Report completo

---

# Ferramentas Utilizadas
| Microsoft Sentinel | SIEM — detecção e investigação |
| KQL (Kusto Query Language) | Query language para log analysis |
| Azure AD Sign-in Logs | Fonte de dados de identidade |
| AbuseIPDB | IOC enrichment de IPs suspeitos |
| ipinfo.io | Geolocalização de IPs |
| MITRE ATT&CK Navigator | Mapeamento de técnicas do ataque |

---

# MITRE ATT&CK

| Initial Access | T1078 | Valid Accounts | Uso de credencial legítima comprometida |
| Credential Access | T1110.003 | Password Spraying | Múltiplas tentativas com senhas comuns |
| Persistence | T1556 | MFA Manipulation | Bypass de autenticação multifator |

---

# Queries KQL

# Query 1 — Detectar Password Spray
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize
    TotalFalhas      = count(),
    UsuariosAfetados = dcount(UserPrincipalName),
    PrimeiroEvento   = min(TimeGenerated),
    UltimoEvento     = max(TimeGenerated),
    ListaUsuarios    = make_set(UserPrincipalName, 5)
    by IPAddress
| where TotalFalhas > 20 and UsuariosAfetados > 5
| extend
    DuracaoMinutos = datetime_diff('minute', UltimoEvento, PrimeiroEvento),
    RiscoNivel = case(
        TotalFalhas > 500, "🔴 CRITICO",
        TotalFalhas > 100, "🟠 ALTO",
        TotalFalhas > 20,  "🟡 MEDIO",
        "🟢 BAIXO")
| project
    IPAddress,
    RiscoNivel,
    TotalFalhas,
    UsuariosAfetados,
    DuracaoMinutos,
    PrimeiroEvento,
    UltimoEvento,
    ListaUsuarios
| sort by TotalFalhas desc
```

### Query 2 — Conta Comprometida (Login após Falhas)
```kql
let IPsSuspeitos = SigninLogs
    | where TimeGenerated > ago(2h)
    | where ResultType != 0
    | summarize Falhas = count() by IPAddress
    | where Falhas > 15
    | project IPAddress;
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == 0
| where IPAddress in (IPsSuspeitos)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName
| order by TimeGenerated desc
```

---

# Timeline do Incidente
| 14:32 | Início das tentativas de login — IP 45.33.32.156 (Romênia) |
| 14:44 | 847 falhas acumuladas — alerta disparado no Sentinel |
| 14:45 | Login bem-sucedido — conta user@empresa.com |
| 14:47 | Analista N1 recebe alerta e inicia investigação |
| 14:52 | IP bloqueado via Conditional Access Policy |
| 14:55 | Senha resetada + MFA forçado nas contas afetadas |
| 15:10 | Incidente contido — nenhuma exfiltração confirmada |

---

# IOCs Identificados
| IP | 45.33.32.156 | 🔴 Malicioso — AbuseIPDB score 100 |
| IP | 91.108.4.0/22 | 🔴 Malicioso — ASN suspeito |
| País de origem | Romênia (RO) | ⚠️ Nunca visto nos logs anteriores |
| Horário | 14:32–14:44 UTC | ⚠️ Fora do horário comercial |

---

# Resposta ao Incidente
### Contenção
- ✅ IP bloqueado via Conditional Access Policy no Azure AD
- ✅ Sessões ativas encerradas nas contas afetadas
- ✅ Senhas resetadas para os 3 usuários comprometidos
### Erradicação
- ✅ MFA habilitado e forçado em todas as contas
- ✅ Revisão de permissões das contas afetadas
### Lições Aprendidas
- Implementar bloqueio automático após 10 falhas consecutivas
- Criar alerta de login de países não habituais
- Revisar política de senhas — senhas fracas facilitaram o spray

---

# Estrutura do Repositório
```
soc-projeto1-sentinel/
├── README.md
├── queries/
│   ├── password-spray-detection.kql
│   └── compromised-account-detection.kql
└── docs/
    └── incident-report.md
```

---

# Sobre

Projeto desenvolvido como parte do portfólio SOC para vaga de 
Analista de Segurança da Informação — Blue Team.

**Habilidades demonstradas:**
KQL • Microsoft Sentinel • Incident Response • MITRE ATT&CK • 
Log Analysis • IOC Enrichment • Detection Engineering
