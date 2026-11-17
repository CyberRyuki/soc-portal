---
title: "Runbook: reported phishing"
description: Analyse a suspicious email
tags: soc, runbook, phishing, managed
---
# Runbook — Reported phishing

1. Get the original email (`.eml`) with headers.
2. Extract sender, domains, URLs and attachments (SHA256).
3. Look up the IoCs in MISP; if new and confirmed, create a MISP event with the right TLP.
4. Find other recipients and clicks in mail/proxy logs.
5. Block sender/domain with approval and inform affected users.
