import { Link } from 'react-router-dom';
import { Empty, ErrorState, Kpi, Loading } from '@/components/shared';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { nf } from '@/lib/format';
import { useToolMetrics } from '@/services/tools';
import { ccnColor } from './common';
import type { Tool } from '@/types/api';

/** Métricas de código (Lizard): líneas, funciones y complejidad; mapa de archivos proporcional a su tamaño. */
export function MetricsTab({ tool, active }: { tool: Tool; active: boolean }) {
  const q = useToolMetrics(tool.slug, active);
  if (q.isPending) return <Loading rows={1} />;
  if (q.error || !q.data) return <ErrorState error={q.error} compact />;
  const m = q.data;
  if (!m.files.length)
    return <Empty>No hay archivos de código legibles. Súbelos o guarda una copia local de GitHub.</Empty>;
  const X = m.totals;
  const max = Math.max(1, ...m.files.map((f) => f.nloc));
  const fileId = (p: string) => tool.files.find((x) => x.path === p)?.id;
  return (
    <div>
      <div className="mb-4 grid grid-cols-2 gap-2.5 md:grid-cols-4">
        <Kpi title="Líneas de código" value={nf(X.nloc)} hint={`${X.files} archivos`} />
        <Kpi title="Funciones" value={nf(X.functions)} />
        <Kpi
          title="Complejidad media"
          value={X.ccn_avg}
          hint="ciclomática ponderada por líneas"
          alert={X.ccn_avg > 10}
        />
        <Kpi
          title="Funciones complejas"
          value={nf(X.complejas)}
          hint="complejidad > 15"
          alert={X.complejas > 0}
        />
      </div>
      <div className="mb-1.5 flex items-baseline justify-between">
        <b>Mapa de archivos</b>
        <span className="text-xs text-muted">tamaño = líneas · color = complejidad máxima</span>
      </div>
      <div className="flex flex-wrap gap-1.5 rounded-xl bg-grid p-2" role="list">
        {m.files.map((f) => {
          const id = fileId(f.path);
          const w = 70 + Math.sqrt(f.nloc / max) * 190;
          const inner = (
            <>
              <span className="block truncate font-mono text-[11px]">{f.path.split('/').pop()}</span>
              <span className="block text-[10.5px] opacity-80">
                {nf(f.nloc)} líneas · máx. {f.ccn_max}
              </span>
            </>
          );
          const style = {
            width: w,
            background: ccnColor(f.ccn_max),
            color: f.ccn_max > 10 ? '#fff' : 'var(--ink)',
          };
          const cls =
            'min-w-0 rounded-lg px-2 py-1.5 text-left leading-tight transition-transform hover:scale-[1.03]';
          return id ? (
            <Link
              key={f.path}
              role="listitem"
              to={`/tools/${tool.slug}/file/${id}`}
              className={cls}
              style={style}
              title={`${f.path} · ${f.functions} funciones · complejidad media ${f.ccn_avg}`}
            >
              {inner}
            </Link>
          ) : (
            <div key={f.path} role="listitem" className={cls} style={style}>
              {inner}
            </div>
          );
        })}
      </div>
      <div className="my-2 flex flex-wrap gap-3 text-xs text-muted">
        {(
          [
            ['≤ 5', 'var(--q2)'],
            ['6–10', 'var(--q4)'],
            ['11–15', 'var(--st-warn)'],
            ['16–25', 'var(--st-serious)'],
            ['> 25', 'var(--st-crit)'],
          ] as const
        ).map(([l, c]) => (
          <span key={l} className="inline-flex items-center gap-1">
            <i className="inline-block size-2.5 rounded-sm" style={{ background: c }} />
            {l}
          </span>
        ))}
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <b>Funciones más complejas</b>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Función</TableHead>
                <TableHead className="text-right">Complejidad</TableHead>
                <TableHead className="text-right">Líneas</TableHead>
                <TableHead className="text-right">Parám.</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {m.top_functions.slice(0, 12).map((f, i) => (
                <TableRow key={i}>
                  <TableCell>
                    <b className="mono">{f.name}</b>
                    <div className="mono text-[11.5px] text-muted">
                      {f.path}:{f.line}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <span
                      className="inline-grid size-6 place-items-center rounded-md text-[11.5px] font-bold text-white"
                      style={{ background: ccnColor(f.ccn) }}
                    >
                      {f.ccn}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">{f.nloc}</TableCell>
                  <TableCell className="text-right">{f.params}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <div>
          <b>Archivos</b>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Archivo</TableHead>
                <TableHead className="text-right">Líneas</TableHead>
                <TableHead className="text-right">Func.</TableHead>
                <TableHead className="text-right">Media</TableHead>
                <TableHead className="text-right">Máx.</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {m.files.slice(0, 15).map((f) => (
                <TableRow key={f.path}>
                  <TableCell className="mono break-all text-xs">
                    {fileId(f.path) ? (
                      <Link className="text-brand" to={`/tools/${tool.slug}/file/${fileId(f.path)}`}>
                        {f.path}
                      </Link>
                    ) : (
                      f.path
                    )}
                  </TableCell>
                  <TableCell className="text-right">{nf(f.nloc)}</TableCell>
                  <TableCell className="text-right">{f.functions}</TableCell>
                  <TableCell className="text-right">{f.ccn_avg}</TableCell>
                  <TableCell className="text-right font-bold" style={{ color: ccnColor(f.ccn_max) }}>
                    {f.ccn_max}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
      <p className="mt-3 text-xs text-muted">
        Métricas calculadas con Lizard (las mismas que usa la extensión Code-XR de VS Code). Una complejidad
        alta no es un fallo de seguridad, pero sí dónde conviene revisar primero.
      </p>
    </div>
  );
}
