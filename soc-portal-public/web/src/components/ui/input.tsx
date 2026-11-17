import * as React from 'react';
import { cn } from '@/lib/utils';

export const inputClass =
  'flex h-9 w-full rounded-xl border border-line bg-card px-3 py-1 text-[13.5px] text-ink shadow-xs transition-colors placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 disabled:cursor-not-allowed disabled:opacity-50';

const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input className={cn(inputClass, className)} ref={ref} {...props} />,
);
Input.displayName = 'Input';

const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      className={cn(inputClass, 'h-auto min-h-[84px] py-2 leading-relaxed', className)}
      ref={ref}
      {...props}
    />
  ),
);
Textarea.displayName = 'Textarea';

const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    <select className={cn(inputClass, 'cursor-pointer pr-8', className)} ref={ref} {...props}>
      {children}
    </select>
  ),
);
Select.displayName = 'Select';

export { Input, Textarea, Select };
