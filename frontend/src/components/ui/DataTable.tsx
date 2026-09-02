import { clsx } from 'clsx';
import type { ReactNode } from 'react';
import type { Pagination } from '@/types';

export interface Column<T> {
  key: string;
  header: string;
  sortable?: boolean;
  className?: string;
  render: (row: T) => ReactNode;
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  sort?: string;
  order?: 'asc' | 'desc';
  onSort?: (key: string) => void;
  pagination?: Pagination;
  onPage?: (page: number) => void;
  loading?: boolean;
  empty?: ReactNode;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  sort,
  order,
  onSort,
  pagination,
  onPage,
  loading,
  empty,
}: Props<T>) {
  return (
    <div className="flex flex-col">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr className="border-b border-line text-left">
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={clsx(
                    'px-3 py-2 font-mono text-2xs uppercase tracking-wider text-muted',
                    c.sortable && onSort && 'cursor-pointer select-none hover:text-text',
                    c.className,
                  )}
                  onClick={() => c.sortable && onSort?.(c.key)}
                >
                  <span className="inline-flex items-center gap-1">
                    {c.header}
                    {c.sortable && sort === c.key && (
                      <span className="text-blue">{order === 'asc' ? '▲' : '▼'}</span>
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={rowKey(row)}
                className={clsx(
                  'border-b border-line-soft transition-colors',
                  onRowClick && 'cursor-pointer hover:bg-hover',
                )}
                onClick={() => onRowClick?.(row)}
              >
                {columns.map((c) => (
                  <td key={c.key} className={clsx('px-3 py-2 align-middle', c.className)}>
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {!loading && rows.length === 0 && (
        <div className="py-10 text-center text-sm text-muted">{empty ?? 'No results.'}</div>
      )}

      {pagination && pagination.pages > 1 && (
        <div className="flex items-center justify-between border-t border-line-soft px-3 py-2 font-mono text-2xs text-muted">
          <span>
            {(pagination.page - 1) * pagination.per_page + 1}–
            {Math.min(pagination.page * pagination.per_page, pagination.total)} of {pagination.total}
          </span>
          <div className="flex gap-1">
            <button
              className="btn px-2 py-1"
              disabled={pagination.page <= 1}
              onClick={() => onPage?.(pagination.page - 1)}
            >
              Prev
            </button>
            <button
              className="btn px-2 py-1"
              disabled={pagination.page >= pagination.pages}
              onClick={() => onPage?.(pagination.page + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
