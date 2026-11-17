import * as React from 'react';
import { cn } from '@/lib/utils';

const Table = React.forwardRef<HTMLTableElement, React.HTMLAttributes<HTMLTableElement>>(
  ({ className, ...props }, ref) => (
    <div className="relative w-full overflow-auto scroll-thin">
      <table ref={ref} className={cn('w-full border-collapse text-[13.5px]', className)} {...props} />
    </div>
  ),
);
Table.displayName = 'Table';
const TableHeader = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className={cn('', className)} {...props} />
);
const TableBody = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <tbody className={cn('', className)} {...props} />
);
const TableRow = React.forwardRef<
  HTMLTableRowElement,
  React.HTMLAttributes<HTMLTableRowElement> & { clickable?: boolean }
>(({ className, clickable, ...props }, ref) => (
  <tr
    ref={ref}
    className={cn(
      'border-b border-line last:border-0',
      clickable && 'cursor-pointer hover:bg-brand-soft/60',
      className,
    )}
    {...props}
  />
));
TableRow.displayName = 'TableRow';
const TableHead = ({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th
    className={cn(
      'whitespace-nowrap px-3 py-2 text-left text-[11.5px] font-bold uppercase tracking-wide text-muted',
      className,
    )}
    {...props}
  />
);
const TableCell = ({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn('px-3 py-2 align-middle', className)} {...props} />
);
export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell };
