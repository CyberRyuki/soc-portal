const LOCALE = 'es-DO';

export const nf = (n: number | null | undefined): string => (n ?? 0).toLocaleString(LOCALE);
export const pct = (a: number, b: number): number => (b ? Math.round((a / b) * 100) : 0);
export const short = (n: number): string =>
  n >= 1e6 ? `${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)} M` : n >= 1e4 ? `${Math.round(n / 1e3)} k` : nf(n);

export function toDate(x: string | number | Date): Date {
  if (x instanceof Date) return x;
  if (typeof x === 'number') return new Date(x > 1e12 ? x : x * 1000);
  return new Date(String(x).replace(/([+-]\d\d)(\d\d)$/, '$1:$2'));
}

/** Fecha corta dd/mm hh:mm */
export function fdt(x: string | number | null | undefined): string {
  if (!x) return '—';
  const d = toDate(x);
  return Number.isNaN(d.getTime())
    ? String(x)
    : d.toLocaleString(LOCALE, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

/** Duración en minutos → "45 min", "3 h 10 min", "2 d 4 h" */
export function dur(m: number | null | undefined): string {
  if (m == null) return '—';
  if (m < 60) return `${Math.round(m)} min`;
  if (m < 1440) {
    const r = Math.round(m % 60);
    return `${Math.floor(m / 60)} h${r ? ` ${r} min` : ''}`;
  }
  const h = Math.floor((m % 1440) / 60);
  return `${Math.floor(m / 1440)} d${h ? ` ${h} h` : ''}`;
}

export function since(x: string | number | null | undefined): string {
  if (!x) return '—';
  const d = toDate(x);
  return Number.isNaN(d.getTime()) ? '—' : dur((Date.now() - d.getTime()) / 60000);
}

export const fsize = (b: number | null | undefined): string =>
  b == null
    ? '—'
    : b < 1024
      ? `${b} B`
      : b < 1048576
        ? `${(b / 1024).toFixed(1)} KB`
        : `${(b / 1048576).toFixed(1)} MB`;

export const initials = (s: string | null | undefined): string =>
  String(s || '?')
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((x) => x[0]?.toUpperCase() ?? '')
    .join('');

export const greeting = (name?: string): string => {
  const h = new Date().getHours();
  const g = h < 12 ? 'Buenos días' : h < 19 ? 'Buenas tardes' : 'Buenas noches';
  return name ? `${g}, ${name}` : g;
};

export const todayLong = (): string =>
  new Date().toLocaleDateString(LOCALE, { weekday: 'long', day: 'numeric', month: 'long' });

export function csvDownload<T extends Record<string, unknown>>(
  name: string,
  rows: T[],
  cols: (keyof T & string)[],
): void {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function textDownload(name: string, text: string, type = 'text/markdown'): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}
