import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, FileUp, Upload } from 'lucide-react';
import { toast } from 'sonner';
import { Empty, ErrorState, Panel } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input, Select } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { api, qs } from '@/lib/api';
import { SEVERITIES, SEV_LABEL, type Severity } from '@/lib/constants';
import { fsize, nf } from '@/lib/format';

export interface PenteraItem {
  ext_key: string;
  title: string;
  severity: Severity;
  score: number | null;
  cve: string;
  asset: string;
  port: string;
  solution: string;
  notes: string;
  n_assets: number;
}
interface Preview {
  report_id: number;
  nombre: string;
  formato: 'pdf' | 'json' | 'csv';
  estrategia: string;
  aviso: string;
  items: PenteraItem[];
}
interface Report {
  id: number;
  name: string;
  size: number;
  fmt: string;
  uploaded_by: string;
  at: string;
  items: number;
  imported: number;
}
const MAX_MB = 50;

/** Importa informes de Pentera (PDF, JSON o CSV): vista previa editable y guardado en Vulnerabilidades. */
export function PenteraImport() {
  const { canWrite } = useAuth();
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [prev, setPrev] = useState<Preview | null>(null);
  const [rows, setRows] = useState<(PenteraItem & { on: boolean })[]>([]);
  const reports = useQuery({
    queryKey: ['vulns', 'reports'],
    queryFn: () => api.get<Report[]>('api/vulns/reports'),
  });

  const upload = useMutation({
    mutationFn: (f: File) =>
      api.post<Preview>(`api/vulns/pentera${qs({ filename: f.name })}`, undefined, {
        raw: f,
        headers: { 'Content-Type': f.type || 'application/octet-stream' },
      }),
    onSuccess: (p) => {
      setPrev(p);
      setRows(p.items.map((i) => ({ ...i, on: true })));
      void qc.invalidateQueries({ queryKey: ['vulns', 'reports'] });
      if (!p.items.length) toast.error('No se encontraron hallazgos en el informe');
    },
  });
  const save = useMutation({
    mutationFn: () =>
      api.post<{ nuevas: number; actualizadas: number }>(`api/vulns/pentera/${prev?.report_id}/import`, {
        items: rows.filter((r) => r.on).map(({ on: _on, ...r }) => r),
      }),
    onSuccess: (r) => {
      toast.success(`${r.nuevas} nuevas y ${r.actualizadas} actualizadas en Seguimiento`);
      setPrev(null);
      setRows([]);
      setFile(null);
      void qc.invalidateQueries({ queryKey: ['vulns'] });
      void qc.invalidateQueries({ queryKey: ['home'] });
    },
    onError: (e) => toast.error(e.message),
  });
  const pick = (f: File | undefined) => {
    if (!f) return;
    if (f.size > MAX_MB * 1024 * 1024) return toast.error(`El informe supera ${MAX_MB} MB`);
    setFile(f);
    setPrev(null);
  };
  const edit = (i: number, patch: Partial<PenteraItem & { on: boolean }>) =>
    setRows((rs) => rs.map((r, k) => (k === i ? { ...r, ...patch } : r)));
  const on = rows.filter((r) => r.on);
  const count = (s: Severity) => on.filter((r) => r.severity === s).length;
  const allOn = rows.length > 0 && on.length === rows.length;

  return (
    <div className="space-y-4">
      {canWrite && (
        <Panel
          title="Importar informe de Pentera"
          hint="PDF del informe, o la exportación JSON/CSV de Pentera (más precisa)"
        >
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[280px] flex-1">
              <Label htmlFor="pt-file">Archivo (PDF, JSON o CSV · máx. {MAX_MB} MB)</Label>
              <Input
                id="pt-file"
                type="file"
                accept=".pdf,.json,.csv,application/pdf,application/json,text/csv"
                className="pt-1.5"
                onChange={(e) => pick(e.target.files?.[0])}
              />
            </div>
            <Button disabled={!file || upload.isPending} onClick={() => file && upload.mutate(file)}>
              <FileUp /> {upload.isPending ? 'Leyendo informe…' : 'Leer informe'}
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted">
            Severidad de Pentera (0–10): ≥7.5 Crítica · ≥5 Alta · ≥2.5 Media · menor Baja · 0 informativo (se
            omite). El informe original se guarda y queda enlazado en cada vulnerabilidad. Reimportar un
            informe posterior actualiza las existentes sin tocar su estado, responsable ni notas.
          </p>
          {upload.error && (
            <div className="mt-3">
              <ErrorState error={upload.error} compact />
            </div>
          )}
        </Panel>
      )}

      {prev && (
        <Panel
          title={`Revisión · ${prev.nombre}`}
          hint={`${prev.formato.toUpperCase()}${prev.estrategia ? ` · lectura por ${prev.estrategia}` : ''}`}
          bodyClassName="px-0 pb-0"
          actions={
            <div className="flex items-center gap-2">
              <span className="text-[13px] text-muted">
                {on.length} de {rows.length} · {count('Critical')} críticas · {count('High')} altas
              </span>
              <Button variant="secondary" size="sm" onClick={() => setPrev(null)}>
                Descartar
              </Button>
              <Button size="sm" disabled={!on.length || save.isPending} onClick={() => save.mutate()}>
                <Upload /> Importar {on.length}
              </Button>
            </div>
          }
        >
          {prev.aviso && (
            <div className="mx-4 mb-3 rounded-lg border border-st-warn/40 bg-st-warn/10 p-2.5 text-[13px]">
              {prev.aviso}
            </div>
          )}
          {rows.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">
                    <Checkbox
                      aria-label="Seleccionar todos"
                      checked={allOn ? true : on.length ? 'indeterminate' : false}
                      onCheckedChange={(v) => setRows((rs) => rs.map((r) => ({ ...r, on: v === true })))}
                    />
                  </TableHead>
                  <TableHead>Pentera</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead>Hallazgo</TableHead>
                  <TableHead>Equipos afectados</TableHead>
                  <TableHead>Remediación</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r, i) => (
                  <TableRow key={r.ext_key + i} className={r.on ? '' : 'opacity-45'}>
                    <TableCell>
                      <Checkbox
                        aria-label={`Incluir ${r.title}`}
                        checked={r.on}
                        onCheckedChange={(v) => edit(i, { on: v === true })}
                      />
                    </TableCell>
                    <TableCell className="font-mono text-[13px] font-bold">{r.score ?? '—'}</TableCell>
                    <TableCell>
                      <Select
                        aria-label={`Severidad de ${r.title}`}
                        value={r.severity}
                        onChange={(e) => edit(i, { severity: e.target.value as Severity })}
                        className="h-8 w-[118px] text-[13px]"
                      >
                        {SEVERITIES.map((s) => (
                          <option key={s} value={s}>
                            {SEV_LABEL[s]}
                          </option>
                        ))}
                      </Select>
                    </TableCell>
                    <TableCell className="min-w-[260px]">
                      <Input
                        aria-label="Título"
                        value={r.title}
                        onChange={(e) => edit(i, { title: e.target.value })}
                        className="h-8 text-[13px]"
                      />
                      {(r.cve || r.port) && (
                        <div className="mt-1 text-xs text-muted">
                          {r.cve}
                          {r.cve && r.port && ' · '}
                          {r.port && `puerto ${r.port}`}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="max-w-[220px] text-xs">
                      <div className="line-clamp-2 font-mono" title={r.asset}>
                        {r.asset || <span className="text-muted">—</span>}
                      </div>
                      {r.n_assets > 1 && <div className="text-muted">{r.n_assets} equipos</div>}
                    </TableCell>
                    <TableCell className="max-w-[280px] text-xs text-muted">
                      <div className="line-clamp-2" title={r.solution}>
                        {r.solution || '—'}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty>
              No se reconocieron hallazgos. Si es un PDF, prueba con la exportación JSON o CSV de Pentera
              (Reports → Export).
            </Empty>
          )}
        </Panel>
      )}

      <Panel title="Informes subidos" bodyClassName="px-0 pb-0">
        {reports.error ? (
          <ErrorState error={reports.error} compact />
        ) : reports.data?.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Informe</TableHead>
                <TableHead>Subido por</TableHead>
                <TableHead className="text-right">Hallazgos</TableHead>
                <TableHead className="text-right">Importados</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.data.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="whitespace-nowrap text-muted">{r.at.slice(0, 16)}</TableCell>
                  <TableCell>
                    <b>{r.name}</b>
                    <div className="text-xs text-muted">
                      {r.fmt.toUpperCase()} · {fsize(r.size)}
                    </div>
                  </TableCell>
                  <TableCell>{r.uploaded_by}</TableCell>
                  <TableCell className="text-right">{nf(r.items)}</TableCell>
                  <TableCell className="text-right">
                    {r.imported ? nf(r.imported) : <span className="text-muted">sin importar</span>}
                  </TableCell>
                  <TableCell>
                    <Button size="icon" variant="ghost" asChild>
                      <a href={`/portal/api/vulns/reports/${r.id}/file`} aria-label={`Descargar ${r.name}`}>
                        <Download />
                      </a>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Aún no se ha subido ningún informe de Pentera.</Empty>
        )}
      </Panel>
    </div>
  );
}
