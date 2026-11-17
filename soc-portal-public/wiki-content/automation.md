---
title: Automation (Shuffle SOAR)
description: Playbooks and approval rules
tags: soc, soar, shuffle, managed
---
# Automation — Shuffle

> During the pilot **no containment action is automatic**. Every block requires human approval.
{.is-danger}

## Flow
1. Wazuh sends level ≥ 10 alerts to the `SOC-Wazuh-Alert-Triage` webhook.
2. The workflow extracts IoCs and looks them up in MISP.
3. If there is a match, the team is notified.
4. The analyst follows the runbook and, if needed, opens an [incident](/soc/incidents).

## Workflows
| Workflow | Trigger | Actions | Human approval |
|---|---|---|---|
| SOC-Wazuh-Alert-Triage | Wazuh webhook (level ≥ 10) | Parse IoC → MISP → notify | No (read only) |
| SOC-Containment-IP | Manual / user input | Wazuh active response / firewall | **Yes** |

## Rules
1. Every run is logged in Shuffle → **Executions**.
2. After changing a workflow: export it (⋮ → **Export**), store it in Git and log it below.
3. App credentials live encrypted in Shuffle — never on this Wiki.

## Change log
| Date | Workflow | Change | Owner |
|---|---|---|---|
| | | | |
