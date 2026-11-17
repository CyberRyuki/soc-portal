---
title: Threat intelligence (MISP)
description: MISP sources and trust criteria
tags: soc, misp, cti, managed
---
# Threat intelligence — MISP

> A MISP match is a lead, not a verdict. Always validate source, age and context before acting.
{.is-warning}

## Trust criteria
| Criterion | Use |
|---|---|
| `to_ids = true` | Only these attributes are used for detection |
| Older than 90 days | Review before blocking |
| Threat level *High* | Analysis priority |
| TLP:RED / AMBER | Never publish on open Wiki pages |

## Feeds
Enable approved feeds in **Sync Actions → Feeds** (e.g. CIRCL OSINT, abuse.ch) and national/sector CSIRT feeds covered by an agreement.

## Service accounts
- `soc-service` — *Read Only* role, used by Shuffle, Wazuh and the dashboard.
