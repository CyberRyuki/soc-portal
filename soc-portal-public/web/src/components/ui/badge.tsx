import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-semibold leading-tight whitespace-nowrap',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-brand-soft text-brand',
        gray: 'border-transparent bg-grid text-muted',
        ok: 'border-transparent bg-st-good/15 text-ok',
        warn: 'border-transparent bg-st-warn/20 text-warn',
        bad: 'border-transparent bg-bad/15 text-bad',
        info: 'border-transparent bg-s1/15 text-s1',
        outline: 'border-line text-ink',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);
export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}
export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
