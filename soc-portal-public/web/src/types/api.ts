/* Tipos del contrato con soc-bridge (FastAPI). Derivados de las respuestas reales de la API. */
import type { AgentStatus, IncidentStatus, Severity } from '@/lib/constants';

export type Pair<K = string> = [K, number];
export type Role = 'admin' | 'analyst' | 'viewer';

/* ---------- autenticación ---------- */
export interface Session {
  id: string;
  current: boolean;
  ip: string;
  ua: string;
  created: string;
  last_seen: string;
}
export interface Me {
  id: number;
  username: string;
  display: string;
  email: string;
  source: 'local' | 'ldap';
  role: Role;
  role_name: string;
  enabled: number;
  must_change: number;
  mfa_enabled: number;
  mfa_required: boolean;
  recovery_left: number;
  state: 'ok' | 'change_password' | 'setup_mfa';
  last_login: string | null;
  last_ip: string | null;
  created_at: string;
  pw_changed: string | null;
  locked: boolean;
  sessions: Session[];
  roles: Record<Role, string>;
}
export interface LoginResult {
  ok?: boolean;
  mfa?: boolean;
  token?: string;
  error?: string;
}
export interface MfaSetup {
  secret: string;
  uri: string;
  qr: string;
}
export interface MfaEnabled {
  ok: boolean;
  recovery: string[];
}

export interface Meta {
  user: string;
  display: string;
  role: Role;
  role_name: string;
  severities: Severity[];
  statuses: IncidentStatus[];
  users: string[];
  links: Record<string, string>;
  runbooks: { slug: string; title: string }[];
}

/* ---------- resumen ---------- */
export interface AlertDoc {
  timestamp: string;
  agent?: { name?: string };
  rule?: { id?: string; level?: number; description?: string; mitre?: { id?: string[] } };
  data?: {
    srcip?: string;
    dstip?: string;
    misp?: { value: string; type: string; event_id: string; event_info: string };
  };
  full_log?: string;
}
export interface Summary {
  generado: string;
  agentes: Record<AgentStatus | 'total', number> & { fuente?: string };
  err_agentes: string | null;
  alertas: {
    total: number;
    por_hora: Pair[];
    por_nivel: Pair<number>[];
    top_rules: Pair[];
    top_agents: Pair[];
  };
  err_alertas: string | null;
  misp_hits: AlertDoc[];
  err_misp_hits: string | null;
  misp_eventos: MispEvent[];
  err_misp_eventos: string | null;
  misp_ioc_24h: number;
  err_misp_ioc: string | null;
  workflows: { id: string; name: string; valid: boolean; triggers: string[] }[];
  err_workflows: string | null;
}
export interface IncidentStats {
  open: number;
  closed: number;
  critical_open: number;
}
export interface HomeData {
  summary: Summary;
  links: Record<string, string>;
  user: string;
  incidents: { stats: IncidentStats; recent: Incident[] };
  metrics: Metrics;
  runbooks: RunbookSummary[];
  sites: Site[];
  vulns: { activas: number; vencidas: number; por_severidad: Pair[] };
  iocs: { vistos: number; activos: number };
}

/* ---------- amenazas ---------- */
export type ThreatRange = '24h' | '7d' | '30d';
export interface ThreatRule {
  id: string;
  desc: string;
  nivel: number;
  n: number;
}
export interface Threats {
  rango: ThreatRange;
  min_level: number;
  total: number;
  hist: Pair<number>[];
  niveles: Pair<number>[];
  reglas: ThreatRule[];
  agentes: Pair[];
  tacticas: Pair[];
  tecnicas: { id: string; nombre: string; n: number }[];
  ips: Pair[];
  paises: Pair[];
  grupos: Pair[];
  calor: Pair<number>[];
  recientes: AlertDoc[];
}

/* ---------- agentes ---------- */
export interface Agent {
  id: string;
  name: string;
  ip: string;
  status: AgentStatus;
  os: string;
  version: string;
  group: string;
  last: string;
}
export interface AgentsDetail {
  foto: string;
  total: number;
  estados: Pair<AgentStatus>[];
  so: Pair[];
  versiones: Pair[];
  grupos: Pair[];
  lista: Agent[];
}

/* ---------- inteligencia (MISP / Shuffle) ---------- */
export interface MispEvent {
  id: string;
  info: string;
  date: string;
  threat_level_id: string;
  attribute_count: string;
}
export interface MispAttribute {
  event_id: string;
  event: string;
  type: string;
  category: string;
  to_ids: boolean;
  value: string;
  date: string;
  tags: string[];
}
export interface ShuffleExec {
  workflow: string;
  workflow_id: string;
  id: string;
  status: string;
  started: number;
  completed: number | null;
}
export interface IntelOverview {
  eventos: MispEvent[];
  iocs: { total: number; tipos: Pair[] };
  shuffle: { estados: Pair[]; recientes: ShuffleExec[] };
}
export interface IocLegacySearch {
  q: string;
  misp: MispAttribute[];
  wazuh: { total: number; agentes: Pair[]; alertas: AlertDoc[] };
  incidentes: Incident[];
  intel?: IntelLookup;
}

/* ---------- incidentes ---------- */
export interface IncidentEvent {
  id: number;
  incident_id: number;
  at: string;
  author: string;
  kind: 'created' | 'note' | 'status' | 'severity' | 'owner' | 'edit' | string;
  text: string;
}
export interface Incident {
  id: number;
  code: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  owner: string;
  detected_at: string;
  detected_by: string;
  assets: string;
  summary: string;
  iocs: string;
  root_cause: string;
  lessons: string;
  runbook: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}
export interface IncidentDetail extends Incident {
  events: IncidentEvent[];
}
export interface OpenIncident {
  code: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  owner: string;
  edad_min: number;
  sla_min: number;
  respondido: boolean;
}
export interface Metrics {
  dias: string[];
  creados: number[];
  cerrados: number[];
  mtta_min: number | null;
  mttr_min: number | null;
  n_tta: number;
  n_ttr: number;
  por_severidad: Pair<Severity>[];
  por_runbook: Pair[];
  por_responsable: Pair[];
  sla: Record<Severity, number>;
  vencidos: OpenIncident[];
  abiertos: OpenIncident[];
  total: number;
}

/* ---------- runbooks ---------- */
export interface RunbookSummary {
  id: number;
  slug: string;
  title: string;
  description: string;
  level: string;
  category: string;
  severity: Severity | string;
  mitre: string;
  owasp: string;
  updated_by: string;
  updated_at: string;
}
export interface Runbook extends RunbookSummary {
  body: string;
}

/* ---------- vulnerabilidades ---------- */
export interface WazuhCve {
  cve: string;
  n: number;
  agentes: number;
  score: number | null;
  sev: string;
  paquetes: string[];
}
export interface WazuhVulns {
  fuente: string;
  total: number;
  cves_n: number;
  agentes_n: number;
  severidad: Pair[];
  agentes: Pair[];
  paquetes: Pair[];
  cves: WazuhCve[];
}
export interface WazuhVulnHost {
  agent: string;
  agent_id: string;
  package: string;
  version: string;
  severity: string;
  score: number | null;
  date: string;
  reference: string;
  description: string;
}
export interface Vuln {
  id: number;
  ext_key: string | null;
  source: string;
  cve: string;
  title: string;
  severity: Severity;
  cvss: number | null;
  asset: string;
  package: string;
  port: string;
  solution: string;
  status: string;
  owner: string;
  due_date: string;
  notes: string;
  first_seen: string;
  last_seen: string;
  created_by: string;
  updated_at: string;
}
export interface VulnList {
  rows: Vuln[];
  stats: {
    total: number;
    activas: number;
    vencidas: number;
    por_severidad: Pair[];
    por_estado: Pair[];
    por_origen: Pair[];
    sla_dias: Record<Severity, number>;
  };
  statuses: string[];
  today: string;
}
export interface ScanPreview {
  format: string;
  rows: Partial<Vuln>[];
  total: number;
  skipped?: number;
}

/* ---------- motor de inteligencia (IoC) ---------- */
export interface IntelSource {
  id: number;
  name: string;
  kind: 'feed' | 'misp' | 'manual';
  url: string;
  fmt: string;
  ioc_type: string;
  csv_col: number;
  ref_col: number | null;
  weight: number;
  interval_h: number;
  retention_days: number;
  auth_header: string;
  tlp: string;
  description: string;
  incident: string;
  enabled: number;
  n: number;
  last_run: string | null;
  last_status: string;
  last_added: number;
  created_by: string;
  created_at: string;
}
export interface IntelJob {
  id: number;
  kind: string;
  source_id: number | null;
  status: 'queued' | 'running' | 'done' | 'error';
  done: number;
  added: number;
  msg: string;
  started: string;
  finished: string | null;
  user: string;
  source: string;
}
export interface IntelOverviewData {
  por_tipo: Pair[];
  unicos: number;
  multi: number;
  coincidencias_24h: number;
  coincidencias_7d: number;
  iocs_vistos_7d: number;
  equipos_7d: number;
  fuentes: IntelSource[];
  jobs: IntelJob[];
  correlacion: string | null;
  correlacion_msg: string;
}
export interface IntelOverlap {
  fuentes: { id: number; name: string; n: number }[];
  pares: [number, number, number][];
}
export interface IntelCatalogEntry {
  key: string;
  name: string;
  url: string;
  ioc_type: string;
  weight: number;
  interval_h: number;
  retention_days: number;
  added: boolean;
}
export interface IntelSourceHit {
  id: number;
  name: string;
  weight: number;
  ref: string | null;
  via: string;
  type: string;
}
export interface Sighting {
  value: string;
  type: string;
  n: number;
  agents: Pair[];
  fields: string[];
  first_seen: string;
  last_seen: string;
  rule: string;
  matched: string;
  score: number;
  fuentes: IntelSourceHit[];
}
export interface Enrichment {
  provider: string;
  verdict: 'malicioso' | 'sospechoso' | 'vulnerable' | 'limpio' | 'error' | string;
  score: number | null;
  data: Record<string, unknown>;
}
export interface IntelLookup {
  value: string;
  type: string;
  score: number;
  fuentes: IntelSourceHit[];
  wazuh: number | null;
  misp: MispAttribute[] | null;
  sightings: number;
  sightings_detalle: Sighting[];
  enriquecimiento?: Enrichment[];
  /** Alertas de Sophos Central guardadas que mencionan el indicador (si Sophos está configurado). */
  sophos?: { id: string; raised_at: string; severity: string; endpoint: string; description: string }[];
}
export interface BulkCheckRow {
  value: string;
  type: string;
  score: number;
  fuentes: IntelSourceHit[];
  wazuh: number | null;
  misp: number | null;
  invalid?: boolean;
}
export interface IntelBrowse {
  rows: {
    value: string;
    type: string;
    source: string;
    weight: number;
    ref: string | null;
    added: string;
    expires: string | null;
  }[];
  total: number;
}

/* ---------- portales ---------- */
export interface Site {
  id: number;
  name: string;
  url: string;
  interval_min: number;
  expect_code: number | null;
  keyword: string;
  watch_content: number;
  auto_incident: number;
  owner: string;
  enabled: number;
  state: 'up' | 'down' | 'unknown' | string;
  fails: number;
  last_check: string | null;
  last_code: number | null;
  last_ms: number | null;
  last_error: string;
  ssl_expiry: string | null;
  ssl_error: string;
  content_hash: string | null;
  content_changed: string | null;
  since: string | null;
  uptime24: number | null;
  avg_ms: number | null;
  hist: [number, number, number, number][];
  /** inventario WAF: waf (protegido) · bypass · directo (backend sin WAF) · externo · '' (sin dato) */
  waf: string;
  plan: string;
  public_ip: string;
  backend_ip: string;
  server: string;
  vs: string;
  grp: string;
  change_threshold: number | null;
  /** detección de desfiguración frente a la versión aprobada */
  deface: '' | DefaceLevel;
  deface_pct: number | null;
  deface_reasons: DefaceReason[];
  deface_at: string;
  page_title: string;
  baseline_at: string;
  baseline_by: string;
  deface_text: string;
  visual_level: '' | DefaceLevel;
  visual_pct: number | null;
  visual_at: string;
  visual_base_at: string;
  visual_error: string;
  critical: number;
}
export type DefaceLevel = 'ok' | 'cambio' | 'sospecha' | 'defacement';
export interface DefaceReason {
  nivel: DefaceLevel;
  motivo: string;
}
export interface DefaceDetail {
  nivel: '' | DefaceLevel;
  cambio_pct: number | null;
  desde: string;
  motivos: DefaceReason[];
  base_at: string;
  base_by: string;
  umbral: number;
  vigilado: boolean;
  titulo_base?: string;
  titulo_ahora?: string;
  palabras_base?: number;
  palabras_ahora?: number;
  dominios_base?: string[];
  dominios_ahora?: string[];
  quitado?: string[];
  añadido?: string[];
}
export interface SiteImportRow {
  name: string;
  url: string;
  waf: string;
  plan: string;
  public_ip: string;
  backend_ip: string;
  server: string;
  vs: string;
  grp: string;
  existe?: boolean;
}
export interface SiteEvent {
  id: number;
  site_id: number;
  at: string;
  kind: string;
  text: string;
  name: string;
}
export interface SitesData {
  rows: Site[];
  events: SiteEvent[];
  today: string;
}

/* ---------- asistente IA ---------- */
export interface AiStatus {
  on: boolean;
  provider: string;
  model: string;
  local: boolean;
  redact: boolean;
  tools: string[];
  max_steps: number;
}
export interface AiChat {
  id: string;
  user: string;
  title: string;
  context: string;
  created: string;
  updated: string;
}
export interface AiEvidence {
  ref: string;
  tool: string;
  args: Record<string, unknown>;
  data: string;
}
export interface AiVerdict {
  veredicto: 'verificada' | 'parcial' | 'no_verificada' | 'sin_verificar' | 'error' | string;
  confianza?: number | null;
  problemas?: string[];
  respuesta_corregida?: string;
}
export type AiProposal =
  | {
      tipo: 'incidente';
      title: string;
      severity: Severity;
      summary: string;
      iocs: string;
      assets: string;
      runbook: string;
      detected_by: string;
    }
  | { tipo: 'nota'; code: string; text: string };
export interface AiMeta {
  evidence?: AiEvidence[];
  verdict?: AiVerdict;
  proposals?: AiProposal[];
  tokens?: { in: number; out: number };
  provider?: string;
  model?: string;
  injections?: number;
  ms?: number;
  error?: boolean;
}
export interface AiMessage {
  id: number;
  chat_id: string;
  role: 'user' | 'assistant';
  content: string;
  meta: AiMeta;
  at: string;
}
export interface AiChatDetail extends AiChat {
  messages: AiMessage[];
}
export interface AiEvent {
  kind: 'thinking' | 'tool' | 'warn' | 'verify';
  text?: string;
  name?: string;
  args?: Record<string, unknown>;
  ref?: string;
  t: number;
}
export interface AiRun {
  status: 'running' | 'done' | 'error';
  events: AiEvent[];
  chat: string;
  answer?: string;
  meta?: AiMeta;
  error?: string;
}
export interface AiAuditRow {
  id: number;
  at: string;
  user: string;
  chat_id: string;
  kind: string;
  provider: string;
  model: string;
  tools: string;
  tokens_in: number;
  tokens_out: number;
  verdict: string;
  injections: number;
  ms: number;
}

/* ---------- MITRE ATT&CK / OWASP ---------- */
export interface MitreTechniqueRow {
  id: string;
  name: string;
  subs: number;
  alerts: number;
  runbooks: { slug: string; title: string; level: string }[];
  mark: string;
}
export interface MitreTactic {
  id: string;
  short: string;
  name: string;
  name_es: string;
  techniques: MitreTechniqueRow[];
  alerts: number;
}
export interface MitreMatrix {
  source: string;
  version: string;
  status: string;
  tactics: MitreTactic[];
  stats: {
    tecnicas: number;
    con_alertas: number;
    con_runbook: number;
    detectadas: number;
    parciales: number;
    sin_cobertura: number;
    alertas: number;
  };
  days: number;
  err_wazuh: string | null;
  estados: Record<string, string>;
}
export interface FrameworkMark {
  status?: string;
  note?: string;
  user?: string;
  at?: string;
}
export interface MitreDetail {
  id: string;
  name: string;
  url: string;
  tactics: string[];
  tactics_es: string[];
  platforms: string[];
  sub: boolean;
  desc: string;
  detection: string;
  subtechniques: { id: string; name: string }[];
  source: string;
  runbooks: { slug: string; title: string; level: string }[];
  wazuh: { total: number; recientes: AlertDoc[]; reglas: ThreatRule[]; agentes: Pair[] } | { error: string };
  mark: FrameworkMark;
  estados: Record<string, string>;
}
export interface OwaspItem {
  id: string;
  en: string;
  es: string;
  resumen: string;
  ejemplos: string[];
  controles: string[];
  deteccion: string[];
  herramientas: string[];
  mitre: string[];
  keywords: string[];
  runbooks: { slug: string; title: string; level: string }[];
  mark: FrameworkMark;
  alertas: number;
}
export interface OwaspData {
  items: OwaspItem[];
  web: { desc: string; n: number; ips: number; owasp: string | null }[];
  err_wazuh: string | null;
  estados: Record<string, string>;
  days: number;
}

/* ---------- herramientas ---------- */
export interface ToolRow {
  id: number;
  slug: string;
  name: string;
  category: string;
  description: string;
  repo_url: string;
  language: string;
  license: string;
  version: string;
  tags: string;
  status: string;
  requires_auth: number;
  owner: string;
  stars: number | null;
  updated_at: string;
  updated_by: string;
  platform: string;
  homepage: string;
  files: number;
}
export interface ToolFile {
  id: number;
  tool_id: number;
  path: string;
  size: number | null;
  sha256: string | null;
  source: 'upload' | 'github';
  cached: number;
  uploaded_by: string;
  uploaded_at: string;
}
export interface ToolLog {
  id: number;
  tool_id: number;
  at: string;
  user: string;
  text: string;
}
export interface Tool extends Omit<ToolRow, 'files'> {
  auth_note: string;
  readme: string;
  usage: string;
  gh_branch: string;
  gh_synced: string | null;
  created_by: string;
  created_at: string;
  files: ToolFile[];
  log: ToolLog[];
}
export interface ToolList {
  rows: ToolRow[];
  categorias: string[];
  estados: string[];
  plataformas: string[];
  por_categoria: Record<string, number>;
  por_plataforma: Record<string, number>;
  total: number;
}
export interface ToolCatalogEntry {
  name: string;
  category: string;
  platform: string;
  description: string;
  auth: boolean;
  url: string;
  added: boolean;
}
export interface ToolFileContent extends ToolFile {
  text: string | null;
  lang: string;
  lines: number | null;
}
export interface ToolMetrics {
  files: {
    path: string;
    nloc: number;
    functions: number;
    ccn_avg: number;
    ccn_max: number;
    tokens: number;
  }[];
  top_functions: { path: string; name: string; line: number; ccn: number; nloc: number; params: number }[];
  totals: { files: number; nloc: number; functions: number; ccn_avg: number; complejas: number };
}
export type FindingStatus = 'confirmed' | 'needs_validation' | 'rejected';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  file: string;
  file_id: number;
  line_start: number;
  line_end: number;
  class: string;
  status: FindingStatus;
  severity: FindingSeverity | null;
  boundary: { principal: string; input: string; control: string; result: string; crossed?: string };
  evidence: string;
  impact: string;
  fix: string;
  reason: string;
}
export interface AuditRow {
  id: number;
  profile: string;
  status: 'running' | 'done' | 'error';
  progress: string;
  started: string;
  finished: string | null;
  user: string;
  cost: {
    llamadas?: number;
    tokens_in?: number;
    tokens_out?: number;
    archivos?: number;
    candidatos?: number;
  };
  error: string;
  counts: Record<'confirmed' | 'needs_validation' | FindingSeverity, number>;
}
export interface AuditList {
  rows: AuditRow[];
  profiles: Record<string, { files: number; chunk: number; label: string }>;
  ai: boolean;
  local: boolean;
}
export interface Audit extends Omit<AuditRow, 'counts'> {
  tool_id: number;
  recon: {
    proposito?: string;
    lenguajes?: string[];
    puntos_entrada?: string[];
    fronteras?: string[];
    prioridad?: string[];
  };
  signals: { file: string; file_id: number; line: number; type: string; code: string }[];
  findings: Finding[];
  report: string;
}
export interface SecuritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  needs_validation: number;
  auditadas: number;
}

/* ---------- contactos / admin ---------- */
export interface Contact {
  id?: number;
  role: string;
  name: string;
  phone: string;
  email: string;
  hours: string;
  sort?: number;
}
export interface AdminUser {
  id: number;
  username: string;
  display: string;
  email: string;
  source: 'local' | 'ldap';
  role: Role;
  enabled: number;
  must_change: number;
  mfa_enabled: number;
  locked: boolean;
  locked_until: number;
  failed: number;
  last_login: string | null;
  last_ip: string | null;
  created_at: string;
}
export interface AdminUsers {
  rows: AdminUser[];
  roles: Record<Role, string>;
  stats: {
    usuarios: number;
    sesiones: number;
    logins_24h: number;
    fallos_24h: number;
    bloqueados: number;
    sin_mfa: number;
    ldap: boolean;
    politica: { max_fails: number; lock_min: number; mfa_roles: Role[]; idle_min: number; max_hours: number };
  };
}
export interface AuthLogRow {
  id: number;
  at: string;
  user: string;
  event: string;
  ip: string;
  ua: string;
  detail: string;
}

// ---------------------------------------------------------------- Sophos Central
export type SophosSeverity = 'low' | 'medium' | 'high';
export interface SophosStatus {
  configurado: boolean;
  conectado?: boolean;
  error?: string;
  tenant?: string;
  region?: string;
  tipo?: string;
  ultima_sync?: string;
  sync_msg?: string;
  web_tag?: string;
  four_eyes?: boolean;
  solo_lectura?: boolean;
  auto_incidente?: string;
  poll_min?: number;
  pendientes?: number;
}
export interface SophosAlert {
  id: string;
  raised_at: string;
  severity: SophosSeverity;
  category: string;
  type: string;
  product: string;
  description: string;
  endpoint_id: string;
  endpoint: string;
  person: string;
  allowed: string[];
  iocs: string[];
  matches: Record<string, number>;
  incident: string;
  state: string;
}
export interface SophosAlerts {
  items: SophosAlert[];
  stats: {
    severidad: [string, number][];
    categorias: [string, number][];
    equipos: [string, number][];
    con_ioc: number;
  };
}
export interface SophosEndpoint {
  id: string;
  hostname: string;
  type: string;
  os: string;
  ip: string;
  person: string;
  health: 'good' | 'suspicious' | 'bad' | 'unknown';
  threats: string;
  services: string;
  isolation: 'isolated' | 'notIsolated' | string;
  tamper: boolean | null;
  last_seen: string;
  products: string[];
}
export interface SophosBlocked {
  hashes: { id: string; sha256: string; comment: string; created: string; by: string }[];
  web: { id: string; url: string; tags: string[]; comment: string }[];
  web_tag: string;
}
export type SophosActionKind =
  | 'isolate'
  | 'unisolate'
  | 'scan'
  | 'alert_action'
  | 'block_hash'
  | 'block_web'
  | 'unblock_hash'
  | 'unblock_web';
export interface SophosAction {
  id: number;
  at: string;
  requested_by: string;
  origin: 'portal' | 'shuffle' | string;
  kind: SophosActionKind;
  nombre: string;
  contencion: boolean;
  target: Record<string, unknown>;
  label: string;
  reason: string;
  incident: string;
  status: 'pending' | 'running' | 'done' | 'failed' | 'rejected';
  decided_by: string;
  decided_at: string;
  result: string;
}

// ---------------------------------------------------------------- Microsoft 365
export interface M365Status {
  configurado: boolean;
  conectado?: boolean;
  error?: string;
  organizacion?: string;
  dominios?: string[];
  ultima_sync?: string;
  sync_msg?: string;
  solo_lectura?: boolean;
  four_eyes?: boolean;
  poll_min?: number;
  sugerir?: string;
  pais?: string;
  pendientes?: number;
}
export interface M365Alert {
  id: string;
  created: string;
  updated: string;
  severity: 'informational' | 'low' | 'medium' | 'high';
  status: 'new' | 'inProgress' | 'resolved' | string;
  title: string;
  category: string;
  service: string;
  detection: string;
  incident_id: string;
  url: string;
  users: string[];
  ips: string[];
  urls: string[];
  mitre: string[];
  description: string;
  recommended: string;
  matches: Record<string, number>;
  classification: string;
}
export interface M365Alerts {
  items: M365Alert[];
  stats: { severidad: [string, number][]; servicio: [string, number][]; abiertas: number };
}
export interface M365SignIn {
  at: string;
  user: string;
  app: string;
  ip: string;
  country: string;
  city: string;
  ok: boolean;
  error: string;
  code: number | null;
  risk: string;
  ca: string;
  client: string;
  foreign: boolean;
}
export interface M365SignIns {
  total: number;
  fallidos: number;
  items: M365SignIn[];
  por_usuario: [string, number][];
  por_pais: [string, number][];
  por_ip: [string, number][];
  extranjero_ok: number;
  riesgo: number;
  truncado: boolean;
}
export interface M365Risky {
  usuarios: {
    id: string;
    upn: string;
    name: string;
    level: string;
    state: string;
    detail: string;
    updated: string;
  }[];
  detecciones: {
    at: string;
    upn: string;
    type: string;
    level: string;
    ip: string;
    country: string;
    state: string;
  }[];
}
export interface M365Posture {
  score: number | null;
  max: number | null;
  fecha: string;
  comparativa: { tipo: string; media: number }[];
  recomendaciones: {
    control: string;
    title: string;
    category: string;
    score: number;
    max: number;
    gain: number;
    impact: string;
    cost: string;
    url: string;
  }[];
  servicios: { service: string; status: string }[];
  incidencias: { id: string; title: string; service: string; status: string; class: string; start: string }[];
}
export interface M365Audit {
  at: string;
  activity: string;
  category: string;
  by: string;
  target: string;
  result: string;
  sensible: boolean;
}
export interface M365Rule {
  user_id: string;
  upn: string;
  rule_id: string;
  name: string;
  enabled: boolean;
  externos: string[];
  oculta: boolean;
  nivel: 'alto' | 'medio';
  condiciones: string;
}
export interface M365RulesScan {
  at: string;
  usuarios: number;
  revisados: number;
  sin_buzon: number;
  reglas: M365Rule[];
}
export type M365ActionKind =
  | 'revoke_sessions'
  | 'disable_user'
  | 'enable_user'
  | 'force_password'
  | 'confirm_compromised'
  | 'dismiss_risk'
  | 'resolve_alert'
  | 'disable_rule';
export interface M365Action {
  id: number;
  at: string;
  requested_by: string;
  origin: string;
  kind: M365ActionKind;
  nombre: string;
  contencion: boolean;
  target: Record<string, unknown>;
  label: string;
  reason: string;
  incident: string;
  status: 'pending' | 'running' | 'done' | 'failed' | 'rejected';
  decided_by: string;
  decided_at: string;
  result: string;
}

// ---------------------------------------------------------------- Resumen ampliado
export interface Overview {
  generado: string;
  sugerencias: {
    pendientes: number;
    criticas: number;
    top: { id: number; title: string; severity: string; source: string; n: number }[];
  };
  portales: {
    total: number;
    activos: number;
    en_linea: number;
    caidos: number;
    desfigurados: number;
    sospecha: number;
    sin_waf: number;
    sin_waf_con_problema: number;
    ssl30: number;
    alertas: { name: string; estado: string; waf: string }[];
  };
  sophos: {
    configurado: boolean;
    alertas_24h?: number;
    altas_24h?: number;
    equipos?: number;
    salud_mala?: number;
    aislados?: number;
    pendientes?: number;
    ultima_sync?: string;
    sync_msg?: string;
  };
  m365: {
    configurado: boolean;
    abiertas?: number;
    altas?: number;
    usuarios_riesgo?: number | null;
    reglas_sospechosas?: number | null;
    pendientes?: number;
    ultima_sync?: string;
    sync_msg?: string;
  };
  exposicion?: {
    configurado: boolean;
    criticos: number;
    altos: number;
    shadow: number;
    servicios: number;
    con_cve: number;
    ultimo: string;
  };
  vulns: {
    criticas: number;
    altas: number;
    activas: number;
    vencidas: number;
    pentera_abiertas: number;
    ultimo_informe: { id: number; name: string; at: string; items: number; imported: number } | null;
  };
  integraciones: {
    name: string;
    estado: 'ok' | 'aviso' | 'error' | 'off';
    detalle: string;
    ultima: string;
    to: string;
  }[];
  acciones_pendientes: number;
  riesgo: {
    puntuacion: number;
    nivel: 'Bajo' | 'Moderado' | 'Alto' | 'Crítico';
    factores: { factor: string; n: number; puntos: number; to: string }[];
  };
  incidentes: { abiertos: number; criticos: number; altos: number; sla_vencidos: number };
  timeline: { at: string; fuente: string; tipo: string; texto: string; to: string }[];
}

// ---------------------------------------------------------------- Exposición / Shadow IT
export type ExpSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface ExpJob {
  id: number;
  at: string;
  by: string;
  kind: 'pasivo' | 'completo';
  status: 'running' | 'done' | 'failed' | 'cancelled';
  phase: string;
  done: number;
  total: number;
  msg: string;
  finished: string;
  stats: Record<string, number>;
}
export interface ExpSummary {
  hallazgos: Partial<Record<ExpSeverity, number>>;
  abiertos: number;
  shadow: number;
  categorias: [string, number][];
  puertos: [string, number][];
  activos: number;
  servicios: number;
  con_cve: number;
  ultimo: ExpJob | null;
  en_curso: number | null;
  alcance: { dominios: number; rangos: string[]; perfil: string; autorizado: boolean; motivo: string };
}
export interface ExpFinding {
  key: string;
  asset: string;
  severity: ExpSeverity;
  category: 'shadow' | 'puerto' | 'web' | 'cve' | 'tls' | string;
  title: string;
  detail: string;
  evidence: string;
  first_seen: string;
  last_seen: string;
  status: 'open' | 'accepted' | 'fixed';
  note: string;
  decided_by: string;
}
export interface ExpAsset {
  key: string;
  type: 'host' | 'ip';
  value: string;
  ips: string[];
  sources: string[];
  first_seen: string;
  last_seen: string;
  inventoried: number;
  in_scope: number;
  status: 'nuevo' | 'conocido' | 'ignorado';
  note: string;
  web: Record<
    string,
    {
      status?: number;
      title?: string;
      server?: string;
      login?: boolean;
      hits?: { path: string; title: string }[];
    }
  >;
  idb: { ports?: number[]; vulns?: string[]; cpes?: string[]; hostnames?: string[] };
  hallazgos: number;
  servicios: number[];
}
export interface ExpService {
  ip: string;
  port: number;
  service: string;
  banner: string;
  tls: { expiry?: string; days?: number; expired?: boolean; issuer?: string; self_signed?: boolean };
  source: string;
  first_seen: string;
  last_seen: string;
  riesgo: string;
  en_alcance: boolean;
}
export interface ExpConfig {
  dominios: string[];
  rangos: string[];
  excluidos: string[];
  perfil: 'pasivo' | 'estandar' | 'amplio' | 'completo';
  velocidad: number;
  concurrencia: number;
  timeout_ms: number;
  rutas_web: boolean;
  programado_dias: number;
  autorizacion: {
    por: string;
    referencia: string;
    hasta: string;
    registrado_por: string;
    registrado_at: string;
  };
  perfiles: Record<string, number>;
  max_ips: number;
}
