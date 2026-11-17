import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';

/** Lee y escribe un parámetro de la URL (la URL es la fuente de verdad de los filtros). */
export function useSearchParam(key: string, fallback = ''): [string, (v: string) => void] {
  const [sp, setSp] = useSearchParams();
  const value = sp.get(key) ?? fallback;
  const set = useCallback(
    (v: string) => {
      setSp(
        (prev) => {
          const n = new URLSearchParams(prev);
          if (v === '' || v === fallback) n.delete(key);
          else n.set(key, v);
          return n;
        },
        { replace: true },
      );
    },
    [key, fallback, setSp],
  );
  return [value, set];
}
