import * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cn } from '@/lib/utils';

const Tabs = TabsPrimitive.Root;
const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.List
    ref={ref}
    className={cn(
      'inline-flex flex-wrap items-center rounded-xl border border-line bg-card p-0.5',
      className,
    )}
    {...props}
  />
));
TabsList.displayName = 'TabsList';
const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      'inline-flex cursor-pointer items-center gap-1.5 rounded-[10px] px-3 py-1.5 text-[13px] font-semibold text-muted transition-colors hover:text-ink data-[state=active]:bg-brand-soft data-[state=active]:text-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 [&_svg]:size-3.5',
      className,
    )}
    {...props}
  />
));
TabsTrigger.displayName = 'TabsTrigger';
const TabsContent = TabsPrimitive.Content;
export { Tabs, TabsList, TabsTrigger, TabsContent };
