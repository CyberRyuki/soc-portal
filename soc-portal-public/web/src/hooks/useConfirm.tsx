import { useCallback, useState } from 'react';
import { ConfirmDialog } from '@/components/ui/alert-dialog';

interface Pending {
  title: string;
  description?: React.ReactNode;
  confirmText?: string;
  destructive?: boolean;
  resolve: (ok: boolean) => void;
}
/** `const [confirm, dialog] = useConfirm(); if (await confirm({title: '…'})) …` */
export function useConfirm(): [(o: Omit<Pending, 'resolve'>) => Promise<boolean>, React.ReactNode] {
  const [p, setP] = useState<Pending | null>(null);
  const confirm = useCallback(
    (o: Omit<Pending, 'resolve'>) => new Promise<boolean>((resolve) => setP({ ...o, resolve })),
    [],
  );
  const dialog = p ? (
    <ConfirmDialog
      open
      onOpenChange={(o) => {
        if (!o) {
          p.resolve(false);
          setP(null);
        }
      }}
      title={p.title}
      description={p.description}
      confirmText={p.confirmText}
      destructive={p.destructive}
      onConfirm={() => {
        p.resolve(true);
        setP(null);
      }}
    />
  ) : null;
  return [confirm, dialog];
}
