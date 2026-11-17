import { isRouteErrorResponse, Link, useRouteError } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';

/** Pantalla de error global del enrutador (errores no controlados en una página). */
export function ErrorPage() {
  const err = useRouteError();
  const msg = isRouteErrorResponse(err)
    ? `${err.status} ${err.statusText}`
    : err instanceof Error
      ? err.message
      : 'Error inesperado';
  return (
    <div className="grid min-h-screen place-items-center p-6">
      <div className="card max-w-md p-8 text-center">
        <AlertTriangle className="mx-auto size-10 text-bad" />
        <h1 className="mt-3 text-lg font-bold">Algo salió mal</h1>
        <p className="mt-1 text-[13.5px] text-muted">{msg}</p>
        <div className="mt-5 flex justify-center gap-2">
          <Button variant="secondary" onClick={() => location.reload()}>
            Recargar
          </Button>
          <Button asChild>
            <Link to="/">Ir al resumen</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
