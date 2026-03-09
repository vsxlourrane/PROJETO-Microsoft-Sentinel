# 📋 Incident Report — Password Spray Attack
**ID do Incidente:** INC-2026-001  
**Data:** 09/03/2026  
**Analista:** Lourrane Xavier  
**Severidade:** 🔴 CRÍTICA  
**Status:** ✅ Contido  

---

## 1. Resumo Executivo

Ataque de Password Spray detectado contra contas do Azure AD.
Um IP localizado na Romênia realizou 847 tentativas de login
em 12 minutos contra múltiplos usuários. Três contas foram
comprometidas antes da contenção. Nenhuma exfiltração de dados
foi confirmada.

---

## 2. Timeline do Incidente

| Horário (UTC) | Evento |
|---|---|
| 14:32 | Início das tentativas — IP 45.33.32.156 |
| 14:38 | 400 falhas acumuladas |
| 14:44 | 847 falhas — alerta disparado no Sentinel |
| 14:45 | Login bem-sucedido — conta comprometida |
| 14:47 | Analista N1 inicia investigação |
| 14:52 | IP bloqueado via Conditional Access |
| 14:55 | Senhas resetadas + MFA forçado |
| 15:10 | Incidente contido |

---

## 3. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Reputação |
|---|---|---|
| IP | 45.33.32.156 | 🔴 AbuseIPDB score 100 |
| IP | 91.108.4.0/22 | 🔴 ASN suspeito |
| País | Romênia (RO) | ⚠️ Nunca visto nos logs |
| Horário | 14:32–14:44 UTC | ⚠️ Fora do horário comercial |

---

## 4. Análise Técnica

### Tipo de Ataque
Password Spray — técnica onde um atacante testa
uma mesma senha fraca contra muitos usuários diferentes
para evitar bloqueio por tentativas excessivas.

### Por que é diferente de Brute Force?
| | Brute Force | Password Spray |
|---|---|---|
| Alvo | 1 usuário | Muitos usuários |
| Senhas testadas | Muitas | Poucas (1 a 3) |
| Risco de bloqueio | Alto | Baixo |
| Detecção | Fácil | Difícil |

### Técnicas MITRE ATT&CK
| ID | Técnica | Evidência |
|---|---|---|
| T1110.003 | Password Spraying | 847 falhas de 1 IP para N usuários |
| T1078 | Valid Accounts | Login bem-sucedido pós-spray |
| T1556 | MFA Manipulation | Acesso sem segundo fator |

---

## 5. Resposta ao Incidente

### Contenção ✅
- IP 45.33.32.156 bloqueado via Conditional Access Policy
- Todas as sessões ativas encerradas
- Contas afetadas desabilitadas temporariamente

### Erradicação ✅
- Senhas resetadas nas 3 contas comprometidas
- MFA habilitado e forçado em todas as contas
- Revisão de permissões das contas afetadas

### Recuperação ✅
- Contas reabilitadas após reset de senha
- Monitoramento intensificado por 72h
- Nenhuma exfiltração confirmada

---

## 6. Lições Aprendidas

| # | Problema Identificado | Recomendação |
|---|---|---|
| 1 | Sem bloqueio automático após falhas | Implementar lock após 10 tentativas |
| 2 | MFA não era obrigatório | Forçar MFA para todos os usuários |
| 3 | Senhas fracas facilitaram o spray | Política de senha forte obrigatória |
| 4 | Sem alerta de login por país novo | Criar regra de geo-anomalia no Sentinel |

---

## 7. Queries KQL Utilizadas

- `queries/password-spray-detection.kql`
- `queries/compromised-account-detection.kql`

---

*Relatório gerado como parte do SOC Portfolio — Blue Team*
