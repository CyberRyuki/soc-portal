export const TOOL_NAME: Record<string, string> = {
  resumen_soc: 'Resumen del SOC',
  buscar_alertas: 'Alertas Wazuh',
  amenazas: 'Panorama de amenazas',
  comprobar_ioc: 'Comprobar IoC',
  analizar_ioc: 'Análisis de IoC',
  buscar_misp: 'Búsqueda MISP',
  incidentes: 'Incidentes',
  ver_incidente: 'Detalle de incidente',
  buscar_runbooks: 'Runbooks',
  ver_runbook: 'Runbook',
  tecnica_mitre: 'Técnica MITRE',
  vulnerabilidades: 'Vulnerabilidades',
  estado_agentes: 'Agentes',
  estado_portales: 'Portales',
  herramientas: 'Herramientas',
  proponer_incidente: 'Propuesta de incidente',
  proponer_nota: 'Propuesta de nota',
};
export const VERDICT: Record<string, [string, 'ok' | 'warn' | 'bad' | 'gray']> = {
  verificada: ['✔ Verificada', 'ok'],
  parcial: ['◐ Verificada en parte', 'warn'],
  no_verificada: ['✕ No verificada', 'bad'],
  sin_verificar: ['Sin verificar', 'gray'],
  error: ['Error', 'bad'],
};
export const STARTERS: [string, string][] = [
  ['🌐', '¿Cómo está el SOC ahora? Resume lo más urgente.'],
  ['🔎', 'Investiga la IP 185.220.101.1: qué hizo en nuestra red y si es peligrosa.'],
  ['🛡', '¿Qué técnicas MITRE se repiten más esta semana y qué runbook aplica a cada una?'],
  ['🧯', 'Revisa los incidentes abiertos con SLA vencido y propón los siguientes pasos.'],
  ['🐞', '¿Qué vulnerabilidades críticas siguen abiertas y en qué equipos?'],
  ['📡', '¿Qué agentes están desconectados y desde cuándo?'],
];
export const argsText = (a: Record<string, unknown> | undefined): string =>
  Object.entries(a ?? {})
    .filter(([, v]) => v !== '' && v != null)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(', ') : String(v)}`)
    .join(' · ');
export const prettyJson = (s: string): string => {
  try {
    return JSON.stringify(JSON.parse(s), null, 2).slice(0, 6000);
  } catch {
    return s;
  }
};
