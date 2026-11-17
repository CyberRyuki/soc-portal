import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Chips, ErrorState, Kpi, KpiGrid, Level, Loading, Markdown, PageHeader } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { SEQ_RAMP } from '@/lib/constants';
import { nf, short } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useMitre, useMitreDetail, useRefreshMitre, useSaveMark } from '@/services/frameworks';
import { LevelPill } from '@/pages/runbooks/common';
import { FrameworkNav, MARK_COLOR, stripCitations } from './common';

export default function MitrePage() {
  const ref = usePageEnter('mitre');
  const { isAdmin, canWrite } = useAuth();
  const [daysS, setDays] = useSearchParam('days', '30');
  const [f, setF] = useSearchParam('f', '');
  const [q, setQ] = useSearchParam('q', '');
  const [t, setT] = useSearchParam('t', '');
  const [draft, setDraft] = useState(q);
  const days = Number(daysS) || 30;
  const m = useMitre(days);
  const refresh = useRefreshMitre();
  useEffect(() => {
    document.title = 'Portal SOC · MITRE ATT&CK';
  }, []);
  if (m.isPending) return <Loading rows={2} h="h-96" />;
  if (m.error || !m.data) return <ErrorState error={m.error} onRetry={() => void m.refetch()} />;
  const M = m.data,
    S = M.stats;
  const text = q.toLowerCase();
  const maxA = Math.max(1, ...M.tactics.flatMap((x) => x.techniques.map((y) => y.alerts)));
  const heat = (n: number) =>
    n ? SEQ_RAMP[Math.min(6, Math.floor(Math.sqrt(n / maxA) * 6.99))] : 'var(--card)';
  const gaps = M.tactics.flatMap((x) => x.techniques).filter((x) => x.alerts && !x.runbooks.length).length;
  const keep = (x: (typeof M.tactics)[number]['techniques'][number]) =>
    (!text || `${x.id} ${x.name}`.toLowerCase().includes(text)) &&
    (!f ||
      (f === 'alertas' && x.alerts) ||
      (f === 'runbook' && x.runbooks.length) ||
      (f === 'sin' && x.mark === 'sin_cobertura') ||
      (f === 'gap' && x.alerts && !x.runbooks.length));
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="MITRE ATT&CK · Enterprise"
        subtitle="Tácticas y técnicas del adversario con las alertas de Wazuh, los runbooks del SOC y la cobertura de detección."
        actions={<FrameworkNav cur="mitre" />}
      />
      <KpiGrid data-enter="">
        <Kpi
          title="Técnicas"
          value={nf(S.tecnicas)}
          hint={M.source === 'stix' ? `ATT&CK v${M.version}` : 'lista básica (sin conexión)'}
        />
        <Kpi
          title={`Con alertas · ${days} d`}
          value={nf(S.con_alertas)}
          hint={`${short(S.alertas)} alertas de Wazuh`}
          onClick={() => setF('alertas')}
        />
        <Kpi
          title="Con runbook"
          value={nf(S.con_runbook)}
          hint="procedimiento de respuesta"
          onClick={() => setF('runbook')}
        />
        <Kpi
          title="Alertas sin runbook"
          value={nf(gaps)}
          hint="huecos a documentar"
          onClick={() => setF('gap')}
          alert={gaps > 0}
        />
        <Kpi
          title="Cobertura marcada"
          value={
            <>
              {nf(S.detectadas)}
              <span className="text-sm font-medium text-muted"> detectadas</span>
            </>
          }
          hint={`${nf(S.parciales)} parciales · ${nf(S.sin_cobertura)} sin cobertura`}
          onClick={() => setF('sin')}
        />
      </KpiGrid>
      <div className="flex flex-wrap items-center gap-2">
        <Chips
          options={[
            ['', 'Todas'],
            ['alertas', 'Con alertas'],
            ['runbook', 'Con runbook'],
            ['gap', 'Alertas sin runbook'],
            ['sin', 'Sin cobertura'],
          ]}
          value={f}
          onChange={setF}
        />
        <Chips
          options={[
            [7, '7 d'],
            [30, '30 d'],
            [90, '90 d'],
          ]}
          value={days}
          onChange={(v) => setDays(String(v))}
        />
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Buscar técnica (T1059, Phishing…) — Enter"
          className="min-w-[200px] flex-1"
          aria-label="Buscar técnica"
        />
        {isAdmin && (
          <Button
            variant="secondary"
            size="sm"
            title="Descargar la última versión de ATT&CK"
            onClick={() =>
              refresh.mutate(undefined, { onSuccess: () => toast('Actualizando ATT&CK en segundo plano') })
            }
          >
            <RefreshCw /> ATT&CK
          </Button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
        Fondo = alertas de Wazuh ({days} d){' '}
        {[0, 2, 4, 6].map((i) => (
          <i key={i} className="inline-block size-2.5 rounded-sm" style={{ background: SEQ_RAMP[i] }} />
        ))}{' '}
        · Borde = cobertura:
        {Object.entries(M.estados).map(([k, v]) => (
          <span key={k} className="inline-flex items-center gap-1">
            <i className="inline-block size-2.5 rounded-sm" style={{ background: MARK_COLOR[k] }} />
            {v}
          </span>
        ))}{' '}
        · 📘 tiene runbook
        {M.err_wazuh && <span className="text-bad">· Wazuh: {M.err_wazuh}</span>}
      </div>
      <div className="overflow-x-auto pb-2 scroll-thin">
        <div className="flex gap-2" style={{ minWidth: M.tactics.length * 172 }}>
          {M.tactics.map((tac) => {
            const items = tac.techniques.filter(keep);
            return (
              <div key={tac.id} className="w-[164px] shrink-0">
                <div className="card mb-1.5 px-2.5 py-2 text-xs" title={`${tac.id} · ${tac.name}`}>
                  <b className="block truncate text-[12.5px]">{tac.name_es}</b>
                  <small className="block truncate text-muted">
                    {tac.name} · {items.length}
                  </small>
                  {tac.alerts > 0 && (
                    <Badge variant="bad" className="mt-1 text-[10.5px]">
                      {short(tac.alerts)}
                    </Badge>
                  )}
                </div>
                <div className="space-y-1">
                  {items.length ? (
                    items.map((x) => (
                      <button
                        key={x.id}
                        type="button"
                        onClick={() => setT(x.id)}
                        title={`${x.id} ${x.name} · ${nf(x.alerts)} alertas · ${x.runbooks.length} runbooks${x.subs ? ` · ${x.subs} subtécnicas` : ''}`}
                        className={cn(
                          'block w-full cursor-pointer rounded-lg border border-line px-2 py-1.5 text-left text-[11.5px] leading-tight transition-colors hover:border-brand',
                          x.alerts / maxA > 0.35 && 'text-white',
                        )}
                        style={{
                          background: heat(x.alerts),
                          borderLeft: x.mark ? `4px solid ${MARK_COLOR[x.mark]}` : undefined,
                        }}
                      >
                        <span className="mono block text-[10.5px] opacity-80">
                          {x.id}
                          {x.runbooks.length > 0 && ' 📘'}
                        </span>
                        {x.name}
                        {x.alerts > 0 && <span className="float-right font-bold">{short(x.alerts)}</span>}
                      </button>
                    ))
                  ) : (
                    <div className="px-2 py-2 text-xs text-muted">—</div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      <p className="text-xs text-muted">
        Las reglas de Wazuh con la táctica antigua «Defense Evasion» aparecen en Sigilo y Debilitamiento de
        defensas. Fuente:{' '}
        <a className="text-brand" href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">
          attack.mitre.org
        </a>{' '}
        {M.status && `· ${M.status}`}
      </p>
      <TechniqueDialog tid={t} days={days} canWrite={canWrite} onClose={() => setT('')} />
    </div>
  );
}

function TechniqueDialog({
  tid,
  days,
  canWrite,
  onClose,
}: {
  tid: string;
  days: number;
  canWrite: boolean;
  onClose: () => void;
}) {
  const base = tid.toUpperCase().split('.')[0] ?? '';
  const q = useMitreDetail(base, days);
  const t = q.data;
  const W = t && !('error' in t.wazuh) ? t.wazuh : null;
  const wErr = t && 'error' in t.wazuh ? t.wazuh.error : '';
  return (
    <Dialog open={!!tid} onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide title={t ? `${t.id} · ${t.name}` : tid}>
        {q.isPending ? (
          <Loading rows={2} />
        ) : q.error || !t ? (
          <ErrorState error={q.error} compact />
        ) : (
          <>
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="flex flex-wrap gap-1">
                {t.tactics_es.map((x) => (
                  <Badge key={x} variant="info">
                    {x}
                  </Badge>
                ))}
                {t.platforms.slice(0, 6).map((p) => (
                  <Badge key={p} variant="gray">
                    {p}
                  </Badge>
                ))}
              </div>
              <Button variant="secondary" size="sm" asChild>
                <a href={t.url} target="_blank" rel="noopener noreferrer">
                  Ver en attack.mitre.org <ExternalLink />
                </a>
              </Button>
            </div>
            {tid.toUpperCase() !== base && (
              <p className="mt-2 text-[13px] text-muted">
                Abierto desde la subtécnica <b>{tid.toUpperCase()}</b>.
              </p>
            )}
            <div className="mt-3 grid gap-4 lg:grid-cols-[2fr_1fr]">
              <div className="text-[13.5px]">
                {t.desc ? (
                  <Markdown src={stripCitations(t.desc)} />
                ) : (
                  <p className="text-muted">
                    Descripción disponible al descargar ATT&CK (necesita salida a Internet).
                  </p>
                )}
                {t.detection && (
                  <>
                    <h3 className="mt-4 font-semibold">Detección (MITRE)</h3>
                    <Markdown className="text-[13px] text-muted" src={stripCitations(t.detection)} />
                  </>
                )}
                {t.subtechniques.length > 0 && (
                  <>
                    <h3 className="mt-4 font-semibold">Subtécnicas</h3>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {t.subtechniques.map((s) => (
                        <a
                          key={s.id}
                          href={`https://attack.mitre.org/techniques/${s.id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={s.name}
                        >
                          <Badge variant="gray">
                            {s.id} {s.name}
                          </Badge>
                        </a>
                      ))}
                    </div>
                  </>
                )}
              </div>
              <div className="space-y-3">
                <CoverageForm
                  key={t.id}
                  tid={t.id}
                  estados={t.estados}
                  mark={t.mark}
                  canWrite={canWrite}
                  onSaved={onClose}
                />
                <section className="rounded-xl border border-line p-3">
                  <h3 className="mb-1 text-[13.5px] font-semibold">
                    Runbooks <span className="text-xs font-normal text-muted">{t.runbooks.length}</span>
                  </h3>
                  {t.runbooks.length ? (
                    t.runbooks.map((r) => (
                      <div key={r.slug} className="py-1 text-[13px]">
                        <Link className="text-brand" to={`/runbooks/${r.slug}`} onClick={onClose}>
                          📘 {r.title}
                        </Link>{' '}
                        <LevelPill v={r.level} />
                      </div>
                    ))
                  ) : (
                    <div className="text-[13px] text-muted">
                      Sin runbook.{' '}
                      <Link className="text-brand" to="/runbooks/new" onClick={onClose}>
                        Crear uno →
                      </Link>
                    </div>
                  )}
                </section>
                <section className="rounded-xl border border-line p-3">
                  <h3 className="mb-1 text-[13.5px] font-semibold">
                    Wazuh <span className="text-xs font-normal text-muted">{days} días</span>
                  </h3>
                  {!W ? (
                    <ErrorState error={wErr} compact />
                  ) : (
                    <>
                      <div className="text-[22px] font-bold">
                        {nf(W.total)} <span className="text-[13px] font-normal text-muted">alertas</span>
                      </div>
                      {W.reglas.slice(0, 6).map((r) => (
                        <div key={r.id} className="flex items-center gap-1.5 py-0.5 text-[12.5px]">
                          <Level l={r.nivel} /> {r.desc}{' '}
                          <span className="text-muted">
                            #{r.id} · {nf(r.n)}
                          </span>
                        </div>
                      ))}
                      {W.agentes.length > 0 && (
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {W.agentes.map(([a, n]) => (
                            <Badge key={a} variant="gray">
                              {a} {nf(n)}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </section>
              </div>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function CoverageForm({
  tid,
  estados,
  mark,
  canWrite,
  onSaved,
}: {
  tid: string;
  estados: Record<string, string>;
  mark: { status?: string; note?: string; user?: string; at?: string };
  canWrite: boolean;
  onSaved: () => void;
}) {
  const save = useSaveMark();
  const [status, setStatus] = useState(mark.status ?? '');
  const [note, setNote] = useState(mark.note ?? '');
  return (
    <section className="rounded-xl border border-line p-3">
      <h3 className="mb-2 text-[13.5px] font-semibold">Cobertura del SOC</h3>
      <Label htmlFor="mk-s">Estado</Label>
      <Select id="mk-s" value={status} onChange={(e) => setStatus(e.target.value)} disabled={!canWrite}>
        <option value="">Sin evaluar</option>
        {Object.entries(estados).map(([k, v]) => (
          <option key={k} value={k}>
            {v}
          </option>
        ))}
      </Select>
      <Textarea
        className="mt-2 min-h-[60px]"
        placeholder="Cómo se detecta (regla Wazuh, Sysmon…), qué falta"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        disabled={!canWrite}
        aria-label="Notas de cobertura"
      />
      <div className="mt-2 flex items-center justify-between">
        <span className="text-[11.5px] text-muted">{mark.user && `${mark.user} · ${mark.at}`}</span>
        {canWrite && (
          <Button
            size="sm"
            disabled={save.isPending}
            onClick={() =>
              save.mutate(
                { fw: 'mitre', key: tid, status, note },
                {
                  onSuccess: () => {
                    toast.success('Cobertura guardada');
                    onSaved();
                  },
                  onError: (e) => toast.error(e.message),
                },
              )
            }
          >
            Guardar
          </Button>
        )}
      </div>
    </section>
  );
}
