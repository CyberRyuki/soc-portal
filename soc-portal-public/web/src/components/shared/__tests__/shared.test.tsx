import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { Chips, ErrorState, HBars, Kpi, SevPill } from '../index';

describe('componentes compartidos', () => {
  it('Kpi enlaza cuando recibe "to" y marca alerta', () => {
    render(
      <MemoryRouter>
        <Kpi title="Críticas" value="5" hint="24 h" to="/threats" alert />
      </MemoryRouter>,
    );
    const link = screen.getByRole('link');
    expect(link).toHaveAttribute('href', '/threats');
    expect(screen.getByText('5')).toHaveClass('text-bad');
  });
  it('Chips informa la opción elegida y la marca como pulsada', async () => {
    const onChange = vi.fn();
    render(
      <Chips
        options={[
          ['24h', '24 h'],
          ['7d', '7 días'],
        ]}
        value="24h"
        onChange={onChange}
      />,
    );
    expect(screen.getByRole('button', { name: '24 h' })).toHaveAttribute('aria-pressed', 'true');
    await userEvent.click(screen.getByRole('button', { name: '7 días' }));
    expect(onChange).toHaveBeenCalledWith('7d');
  });
  it('HBars muestra el estado vacío y los valores', () => {
    const { rerender } = render(<HBars rows={[]} empty="Nada" />);
    expect(screen.getByText('Nada')).toBeInTheDocument();
    rerender(<HBars rows={[{ label: 'sshd', value: 1500 }]} />);
    expect(screen.getByText('sshd')).toBeInTheDocument();
  });
  it('SevPill traduce la severidad', () => {
    render(<SevPill v="Critical" />);
    expect(screen.getByText('Crítica')).toBeInTheDocument();
  });
  it('ErrorState muestra el mensaje y permite reintentar', async () => {
    const retry = vi.fn();
    render(<ErrorState error={new Error('Wazuh caído')} onRetry={retry} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Wazuh caído');
    await userEvent.click(screen.getByRole('button', { name: /reintentar/i }));
    expect(retry).toHaveBeenCalled();
  });
});
