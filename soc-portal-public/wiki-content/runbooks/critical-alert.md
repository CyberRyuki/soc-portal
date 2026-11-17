---
title: "Runbook: critical Wazuh alert"
description: Levels 13–15
tags: soc, runbook, wazuh, managed
---
# Runbook — Critical alert (levels 13–15)

> Notify on-call within **15 minutes**. Contacts: [Contacts & on-call](/soc/contacts).
{.is-danger}

1. Confirm the alert in the Wazuh Dashboard (rule, agent, `full_log`).
2. Check the Shuffle execution and the MISP result.
3. Notify on-call.
4. Preserve evidence (logs, hashes, screenshots) before any containment.
5. Open an incident with the [template](/soc/templates/incident) and keep the timeline.
