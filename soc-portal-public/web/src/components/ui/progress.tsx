import { cn } from '@/lib/utils';
/** Barra de progreso simple con color personalizable. */
export function Bar({
  value,
  max = 100,
  color = 'var(--s1)',
  className,
}: {
  value: number;
  max?: number;
  color?: string;
  className?: string;
}) {
  const w = max ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div
      className={cn('h-1.5 w-full overflow-hidden rounded-full bg-grid', className)}
      role="progressbar"
      aria-valuenow={value}
      aria-valuemax={max}
    >
      <div
        className="h-full rounded-full transition-[width] duration-500"
        style={{ width: `${w}%`, background: color }}
      />
    </div>
  );
}
