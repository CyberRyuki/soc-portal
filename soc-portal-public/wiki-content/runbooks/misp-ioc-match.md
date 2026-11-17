---
title: "Runbook: MISP IoC match"
description: What to do when rule 100622 fires
tags: soc, runbook, misp, managed
---
# Runbook — MISP IoC match (rule 100622)

> A match does not imply automatic blocking.
{.is-warning}

1. **Verify the IoC** in MISP: event, date, source, `to_ids`, TLP tags.
2. **Asset context**: which agent, is it critical, inbound or outbound connection?
3. **Related activity** in Wazuh: same IP or hash in the last 72 h.
4. **Decide**
    - False positive → document it and add a *false-positive* sighting in MISP.
    - True positive → open an incident and request containment (requires approval).
5. **Register a sighting** in MISP to share the finding.
