import { useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import gsap from 'gsap';
import { toast } from 'sonner';
import { Avatar, Empty, SevPill } from '@/components/shared';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { STATUSES, STATUS_LABEL, type IncidentStatus } from '@/lib/constants';
import { dur } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useMoveIncident } from '@/services/incidents';
import type { Incident, OpenIncident } from '@/types/api';

const LANE_COLOR: Record<IncidentStatus, string> = {
  Open: 'var(--st-crit)',
  Investigating: 'var(--st-warn)',
  Contained: 'var(--brand)',
  Closed: 'var(--st-good)',
};
const MOTION = !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

interface Props {
  rows: Incident[];
  open: OpenIncident[];
}
/**
 * Tablero Kanban: arrastrar una tarjeta a otra columna cambia el estado del incidente (PUT).
 * El arrastre usa un clon «fantasma» animado con GSAP y `elementFromPoint` para detectar la columna destino.
 */
export function KanbanBoard({ rows, open }: Props) {
  const nav = useNavigate();
  const { canWrite } = useAuth();
  const move = useMoveIncident();
  const [confirm, dialog] = useConfirm();
  const board = useRef<HTMLDivElement>(null);
  const sla = Object.fromEntries(open.map((o) => [o.code, o]));

  const onPointerDown = useCallback(
    (ev: React.PointerEvent<HTMLDivElement>, inc: Incident) => {
      if (ev.button !== 0) return;
      const card = ev.currentTarget;
      const x0 = ev.clientX,
        y0 = ev.clientY,
        r0 = card.getBoundingClientRect();
      let on = false,
        ghost: HTMLElement | null = null,
        over: HTMLElement | null = null;
      const lanes = Array.from(board.current?.querySelectorAll<HTMLElement>('[data-lane]') ?? []);
      const moveH = (e: PointerEvent) => {
        const dx = e.clientX - x0,
          dy = e.clientY - y0;
        if (!on) {
          if (!canWrite || Math.hypot(dx, dy) < 6) return;
          on = true;
          ghost = card.cloneNode(true) as HTMLElement;
          ghost.classList.add(
            'fixed',
            'z-[100]',
            'pointer-events-none',
            'shadow-2xl',
            'border-brand',
            'cursor-grabbing',
          );
          Object.assign(ghost.style, {
            left: `${r0.left}px`,
            top: `${r0.top}px`,
            width: `${r0.width}px`,
            margin: '0',
          });
          document.body.appendChild(ghost);
          card.classList.add('opacity-25', 'border-dashed');
          if (MOTION)
            gsap.fromTo(
              ghost,
              { scale: 1, rotation: 0 },
              { scale: 1.04, rotation: -2, duration: 0.25, ease: 'back.out(2)' },
            );
        }
        gsap.set(ghost, { x: dx, y: dy });
        const under =
          (document.elementFromPoint(e.clientX, e.clientY) as HTMLElement | null)?.closest<HTMLElement>(
            '[data-lane]',
          ) ?? null;
        if (under !== over) {
          lanes.forEach((l) => l.classList.toggle('ring-2', l === under));
          over = under;
        }
      };
      const upH = async (e: PointerEvent) => {
        removeEventListener('pointermove', moveH);
        removeEventListener('pointerup', upH);
        lanes.forEach((l) => l.classList.remove('ring-2'));
        if (!on) {
          if (Math.hypot(e.clientX - x0, e.clientY - y0) < 6) nav(`/incidents/${inc.code}`);
          return;
        }
        const finish = () => {
          ghost?.remove();
          card.classList.remove('opacity-25', 'border-dashed');
        };
        const to = over?.dataset.lane as IncidentStatus | undefined;
        const back = () =>
          MOTION && ghost
            ? gsap.to(ghost, {
                x: 0,
                y: 0,
                rotation: 0,
                scale: 1,
                duration: 0.3,
                ease: 'power3.out',
                onComplete: finish,
              })
            : finish();
        if (!to || to === inc.status) return back();
        if (
          to === 'Closed' &&
          !(await confirm({
            title: `¿Cerrar ${inc.code}?`,
            description: inc.title,
            confirmText: 'Cerrar incidente',
          }))
        )
          return back();
        if (ghost && over) {
          const r1 = over.getBoundingClientRect();
          gsap.to(ghost, {
            x: r1.left + 10 - r0.left,
            y: r1.top + 50 - r0.top,
            rotation: 0,
            scale: 1,
            duration: 0.25,
            ease: 'power3.out',
            onComplete: finish,
          });
        } else finish();
        try {
          await move.mutateAsync({ code: inc.code, status: to });
          toast.success(`${inc.code} → ${STATUS_LABEL[to]}`);
        } catch (err) {
          toast.error(`No se pudo mover: ${(err as Error).message}`);
        }
      };
      addEventListener('pointermove', moveH);
      addEventListener('pointerup', upH);
    },
    [canWrite, confirm, move, nav],
  );

  return (
    <div ref={board} className="grid gap-3 overflow-x-auto pb-1 md:grid-cols-2 xl:grid-cols-4" data-enter="">
      {STATUSES.map((k) => {
        const list = rows.filter((x) => x.status === k).slice(0, k === 'Closed' ? 20 : 200);
        const total = rows.filter((x) => x.status === k).length;
        return (
          <section
            key={k}
            data-lane={k}
            className={cn(
              'glass relative flex min-h-[360px] flex-col overflow-hidden rounded-2xl border border-line ring-brand/50 transition-shadow',
              k === 'Closed' && 'opacity-90',
            )}
            style={{ ['--lc' as string]: LANE_COLOR[k] }}
            aria-label={`Columna ${STATUS_LABEL[k]}`}
          >
            <div className="absolute inset-x-0 top-0 h-[3px]" style={{ background: LANE_COLOR[k] }} />
            <h4 className="flex items-center gap-2 px-3.5 pb-2.5 pt-3.5 text-[13.5px] font-semibold">
              <i className="size-2.5 rounded-full" style={{ background: LANE_COLOR[k] }} />
              {STATUS_LABEL[k]}
              <em className="ml-auto rounded-full bg-grid px-2 py-0.5 text-[11px] font-bold not-italic">
                {total}
              </em>
            </h4>
            <div className="flex flex-1 flex-col gap-2 px-2.5 pb-3">
              {list.length ? (
                list.map((x) => {
                  const s = sla[x.code];
                  const late = s && !s.respondido && s.edad_min > s.sla_min;
                  return (
                    <div
                      key={x.code}
                      role="button"
                      tabIndex={0}
                      onPointerDown={(e) => onPointerDown(e, x)}
                      onKeyDown={(e) => e.key === 'Enter' && nav(`/incidents/${x.code}`)}
                      className={cn(
                        'card select-none rounded-xl px-3 py-2.5 shadow-sm transition-colors hover:border-brand/50 touch-none',
                        canWrite ? 'cursor-grab' : 'cursor-pointer',
                      )}
                    >
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <b className="mono">{x.code}</b>
                        <SevPill v={x.severity} />
                      </div>
                      <div className="my-1.5 text-[13.5px] font-semibold leading-snug">{x.title}</div>
                      <div className="flex items-center gap-2 text-xs text-muted">
                        <Avatar name={x.owner || '?'} className="size-[22px] rounded-md text-[10px]" />
                        {x.owner || 'sin responsable'}
                        {late ? (
                          <span
                            className="ml-auto font-bold text-bad"
                            title="SLA de primera respuesta vencido"
                          >
                            ⚠ {dur(s.edad_min)}
                          </span>
                        ) : (
                          <span className="ml-auto">{s ? dur(s.edad_min) : x.updated_at.slice(5, 16)}</span>
                        )}
                      </div>
                    </div>
                  );
                })
              ) : (
                <Empty className="py-5 text-xs">Arrastra aquí</Empty>
              )}
            </div>
          </section>
        );
      })}
      {dialog}
    </div>
  );
}
