---
title: Monitoring (Wazuh)
description: How the SOC operates Wazuh
tags: soc, wazuh, managed
---
# Monitoring — Wazuh

> Live agent and alert figures are on **[SOC Status](/soc/status)**.
{.is-info}

# Operation {.tabset}
## Shift checklist
1. Open [SOC Status](/soc/status) and review disconnected agents and critical alerts.
2. Review MISP matches (rule **100622**) and follow the [IoC runbook](/soc/runbooks/misp-ioc-match).
3. Record false positives and propose rule tuning.

## Components
| Component | Port | Purpose |
|---|---|---|
| Indexer | 9200 (local) | Alert storage `wazuh-alerts-*` |
| Manager | 1514/1515, 55000 | Agents and API |
| Dashboard | 443 | Web console |

## Integrations
| Integration | Trigger | Destination |
|---|---|---|
| `shuffle` | Alerts level ≥ 10 | Workflow `SOC-Wazuh-Alert-Triage` |
| `custom-misp.py` | FIM rules 550, 554 | MISP → rule 100622 |
| `custom-graph-mail` | Alerts level ≥ 12 | Email notification |

## Onboarding an agent
Dashboard → **Agents** → **Deploy new agent** → follow the wizard. Register the asset in the inventory.
