export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type IncidentStatus = 'Open' | 'Investigating' | 'Contained' | 'Closed';
export type AgentStatus = 'active' | 'disconnected' | 'never_connected' | 'pending';

export const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low'];
export const STATUSES: IncidentStatus[] = ['Open', 'Investigating', 'Contained', 'Closed'];

export const SEV_LABEL: Record<Severity, string> = {
  Critical: 'Crítica',
  High: 'Alta',
  Medium: 'Media',
  Low: 'Baja',
};
export const STATUS_LABEL: Record<IncidentStatus, string> = {
  Open: 'Abierto',
  Investigating: 'En investigación',
  Contained: 'Contenido',
  Closed: 'Cerrado',
};
export const AGENT_LABEL: Record<AgentStatus, string> = {
  active: 'Activos',
  disconnected: 'Desconectados',
  never_connected: 'Nunca conectados',
  pending: 'Pendientes',
};
export const EXEC_LABEL: Record<string, string> = {
  FINISHED: 'Completada',
  ABORTED: 'Abortada',
  EXECUTING: 'En curso',
  WAITING: 'En espera',
  FAILURE: 'Fallida',
};
export const SEV_COLOR: Record<Severity, string> = {
  Critical: 'var(--st-crit)',
  High: 'var(--st-serious)',
  Medium: 'var(--st-warn)',
  Low: 'var(--s-neutral)',
};
export const AGENT_COLOR: Record<AgentStatus, string> = {
  active: 'var(--st-good)',
  disconnected: 'var(--st-crit)',
  never_connected: 'var(--s-neutral)',
  pending: 'var(--st-warn)',
};
export const levelColor = (l: number): string =>
  l >= 13 ? 'var(--st-crit)' : l >= 10 ? 'var(--st-serious)' : l >= 7 ? 'var(--st-warn)' : 'var(--s-neutral)';
export const LEVEL_GROUPS: [string, number, number, string][] = [
  ['Crítico (13–15)', 13, 15, 'var(--st-crit)'],
  ['Alto (10–12)', 10, 12, 'var(--st-serious)'],
  ['Medio (7–9)', 7, 9, 'var(--st-warn)'],
  ['Bajo (0–6)', 0, 6, 'var(--s-neutral)'],
];
export const VULN_STATUS_LABEL: Record<string, string> = {
  Open: 'Abierta',
  Remediating: 'En remediación',
  Mitigated: 'Mitigada',
  Accepted: 'Riesgo aceptado',
  Closed: 'Cerrada',
};
export const IOC_TYPE_LABEL: Record<string, string> = {
  ip: 'IP',
  cidr: 'Red',
  domain: 'Dominio',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA1',
  sha256: 'SHA256',
  email: 'Correo',
};
export const FIELD_NAMES: Record<string, string> = {
  'rule.id': 'Regla',
  'agent.name': 'Agente',
  'rule.mitre.tactic': 'Táctica MITRE',
  'rule.mitre.id': 'Técnica MITRE',
  'data.srcip': 'IP de origen',
  'GeoLocation.country_name': 'País',
  'rule.level': 'Nivel',
  'rule.groups': 'Grupo',
};
export const SEQ_RAMP = [
  'var(--q1)',
  'var(--q2)',
  'var(--q3)',
  'var(--q4)',
  'var(--q5)',
  'var(--q6)',
  'var(--q7)',
];
export const QUERY_STALE_MS = 60_000;
