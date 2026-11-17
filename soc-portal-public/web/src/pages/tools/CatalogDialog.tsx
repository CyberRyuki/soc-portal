import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Loading } from '@/components/shared';
import { useAddToolCatalog, useToolCatalog } from '@/services/tools';
import { PLAT_ICON } from './common';
import { cn } from '@/lib/utils';

export function CatalogDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const q = useToolCatalog(open);
  const add = useAddToolCatalog();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const rows = useMemo(() => q.data ?? [], [q.data]);
  const by = useMemo(() => {
    const m: Record<string, typeof rows> = {};
    rows.forEach((r) => (m[r.category] ??= []).push(r));
    return m;
  }, [rows]);
  const pend = rows.filter((r) => !r.added);
  const submit = async () => {
    if (!sel.size) return toast.error('Marca alguna herramienta');
    const r = await add.mutateAsync([...sel]);
    toast.success(`${r.añadidas} herramientas añadidas`);
    setSel(new Set());
    onClose();
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        wide
        title="Catálogo de herramientas"
        description={`${rows.length} herramientas · ${pend.length} sin añadir · Selección de GitHub, Kali Linux y Windows (Sysinternals y otras). Las marcadas 🔒 son intrusivas y quedan «En evaluación» con autorización obligatoria.`}
      >
        {q.isPending ? (
          <Loading />
        ) : (
          <div className="max-h-[60vh] overflow-auto scroll-thin">
            {Object.entries(by).map(([c, list]) => (
              <div key={c}>
                <h3 className="mb-1.5 mt-3.5 text-[14px] font-bold">{c}</h3>
                <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {list.map((r) => (
                    <label
                      key={r.name}
                      className={cn(
                        'flex cursor-pointer gap-2.5 rounded-xl border border-line p-2.5',
                        r.added && 'opacity-50',
                      )}
                    >
                      <Checkbox
                        className="mt-0.5"
                        disabled={r.added}
                        checked={r.added || sel.has(r.name)}
                        onCheckedChange={(v) =>
                          setSel((s) => {
                            const n = new Set(s);
                            if (v === true) n.add(r.name);
                            else n.delete(r.name);
                            return n;
                          })
                        }
                      />
                      <span>
                        <b className="text-[13.5px]">{r.name}</b> {r.auth && '🔒'}
                        <div className="text-xs text-muted">
                          {PLAT_ICON[r.platform] ?? ''} {r.platform}
                          {r.added && ' · ya está en el repositorio'}
                        </div>
                        <div className="mt-0.5 text-xs">{r.description}</div>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="mt-4 flex items-center justify-between gap-2">
          <Button variant="secondary" size="sm" onClick={() => setSel(new Set(pend.map((r) => r.name)))}>
            Marcar todas
          </Button>
          <span className="flex gap-2">
            <Button variant="secondary" onClick={onClose}>
              Cerrar
            </Button>
            <Button onClick={submit} disabled={add.isPending}>
              Añadir seleccionadas ({sel.size})
            </Button>
          </span>
        </div>
      </DialogContent>
    </Dialog>
  );
}
