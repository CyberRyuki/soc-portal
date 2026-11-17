import { useEffect, useState } from 'react';
import { Plus, Save, X } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Empty, ErrorState, Loading, PageHeader } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useContacts, useSaveContacts } from '@/services/account';
import type { Contact } from '@/types/api';

const COLS: [keyof Contact & string, string][] = [
  ['role', 'Rol'],
  ['name', 'Nombre'],
  ['phone', 'Teléfono'],
  ['email', 'Correo'],
  ['hours', 'Horario'],
];

export default function ContactsPage() {
  const ref = usePageEnter('contacts');
  const { canWrite } = useAuth();
  const q = useContacts();
  const save = useSaveContacts();
  const [local, setLocal] = useState<Contact[] | null>(null);
  const rows = local ?? q.data ?? [];
  const dirty = local !== null;
  const setRows = (fn: (r: Contact[]) => Contact[]) => setLocal(fn(rows));
  useEffect(() => {
    document.title = 'Portal SOC · Contactos';
  }, []);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const set = (i: number, k: keyof Contact, v: string) =>
    setRows((r) => r.map((c, j) => (j === i ? { ...c, [k]: v } : c)));
  const submit = async () => {
    const bad = rows.find((c) => c.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.email));
    if (bad) return toast.error(`Correo no válido: ${bad.email}`);
    try {
      await save.mutateAsync(
        rows.map((c) => ({
          ...c,
          role: c.role.trim(),
          name: c.name.trim(),
          phone: c.phone.trim(),
          email: c.email.trim(),
          hours: c.hours.trim(),
        })),
      );
      setLocal(null);
      toast.success('Contactos guardados');
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Contactos y guardias"
        subtitle="A quién llamar y cuándo"
        actions={
          canWrite && (
            <>
              <Button
                variant="secondary"
                onClick={() =>
                  setRows((r) => [...r, { role: '', name: '', phone: '', email: '', hours: '' }])
                }
              >
                <Plus /> Añadir fila
              </Button>
              <Button onClick={submit} disabled={save.isPending || !dirty}>
                <Save /> Guardar
              </Button>
            </>
          )
        }
      />
      <section className="card overflow-x-auto">
        {rows.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                {COLS.map(([k, l]) => (
                  <TableHead key={k}>{l}</TableHead>
                ))}
                {canWrite && <TableHead />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((c, i) => (
                <TableRow key={c.id ?? `n${i}`}>
                  {COLS.map(([k]) => (
                    <TableCell key={k} className="px-1.5 py-1">
                      {canWrite ? (
                        <Input
                          value={String(c[k] ?? '')}
                          onChange={(e) => set(i, k, e.target.value)}
                          aria-label={k}
                          className="h-8"
                        />
                      ) : (
                        <span className="px-2">{String(c[k] ?? '')}</span>
                      )}
                    </TableCell>
                  ))}
                  {canWrite && (
                    <TableCell className="px-1">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title="Quitar fila"
                        onClick={() => setRows((r) => r.filter((_, j) => j !== i))}
                      >
                        <X />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin contactos.</Empty>
        )}
      </section>
    </div>
  );
}
