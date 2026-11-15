import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ErrorNotice, DataTable, Badge } from './Common';
describe('Dashboard components', () => {
  it('shows API errors', () => {
    render(<ErrorNotice error={new Error('Нет доступа')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Нет доступа');
  });
  it('renders severity', () => {
    render(<Badge value="CRITICAL" />);
    expect(screen.getByText('CRITICAL')).toHaveClass('red');
  });
  it('opens selected row and handles sort', () => {
    const select = vi.fn(),
      sort = vi.fn();
    render(<DataTable rows={[{
      id: '1',
      name: 'Production'
    }]} columns={['name']} sort="id" onSort={sort} onSelect={select} />);
    fireEvent.click(screen.getByText('Production'));
    expect(select).toHaveBeenCalledWith({
      id: '1',
      name: 'Production'
    });
    fireEvent.click(screen.getByRole('button'));
    expect(sort).toHaveBeenCalledWith('name');
  });
  it('shows empty results', () => {
    render(<DataTable rows={[]} columns={['name']} sort="id" onSort={() => {}} onSelect={() => {}} />);
    expect(screen.getByText(/Записей пока нет/)).toBeInTheDocument();
  });
});
