import * as React from 'react';
import * as DialogPrimitive from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

const Dialog = DialogPrimitive.Root;
const DialogTrigger = DialogPrimitive.Trigger;
const DialogClose = DialogPrimitive.Close;

const DialogContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & {
    wide?: boolean;
    title: string;
    description?: string;
  }
>(({ className, children, wide, title, description, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px] data-[state=open]:animate-in data-[state=open]:fade-in-0" />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        'card fixed left-1/2 top-1/2 z-50 max-h-[92vh] w-[calc(100%-24px)] -translate-x-1/2 -translate-y-1/2 overflow-auto p-5 shadow-2xl focus:outline-none',
        wide ? 'max-w-5xl' : 'max-w-2xl',
        className,
      )}
      {...props}
    >
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <DialogPrimitive.Title className="text-lg font-bold leading-tight">{title}</DialogPrimitive.Title>
          {description ? (
            <DialogPrimitive.Description className="mt-0.5 text-[13px] text-muted">
              {description}
            </DialogPrimitive.Description>
          ) : (
            <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>
          )}
        </div>
        <DialogPrimitive.Close
          className="rounded-lg p-1 text-muted hover:bg-grid hover:text-ink"
          aria-label="Cerrar"
        >
          <X className="size-4" />
        </DialogPrimitive.Close>
      </div>
      {children}
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
DialogContent.displayName = 'DialogContent';
export { Dialog, DialogTrigger, DialogClose, DialogContent };
