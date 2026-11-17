import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { Incident } from '@/types/api';
import { KanbanBoard } from '../KanbanBoard';

vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ canWrite: true }) }));

const inc = (id: number, status: Incident['status'], title: string): Incident => ({
  id,
  code: `INC-${id}`,
  title,
  severity: 'High',
  status,
  owner: 'ana',
  detected_at: '2026-11-17T10:00:00',
  detected_by: 'wazuh',
  assets: '',
  summary: '',
  iocs: '',
  root_cause: '',
  lessons: '',
  runbook: '',
  created_by: 'ana',
  created_at: '2026-11-17T10:00:00',
  updated_at: '2026-11-17T10:00:00',
});

describe('KanbanBoard', () => {
  it('reparte los incidentes en sus columnas', () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <KanbanBoard
            rows={[inc(1, 'Open', 'Fuerza bruta SSH'), inc(2, 'Closed', 'Phishing RRHH')]}
            open={[]}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(
      within(screen.getByLabelText('Columna Abierto')).getByText('Fuerza bruta SSH'),
    ).toBeInTheDocument();
    expect(within(screen.getByLabelText('Columna Cerrado')).getByText('Phishing RRHH')).toBeInTheDocument();
    expect(within(screen.getByLabelText('Columna Contenido')).queryAllByRole('button')).toHaveLength(0);
  });
});
