# Alternativas

`opensoar/` — OpenSOAR (beta, Apache 2.0): compose, setup, playbook `wazuh_misp_triage`
y el script de Wazuh `custom-opensoar.py`. Probado contra el código de opensoar-core
(commit 671896be). Se conserva por si el equipo prefiere playbooks en Python en el futuro.
El portal actual usa **Shuffle**; para cambiar habría que adaptar `bridge/connectors.py`
e `install-integrations.sh`.
