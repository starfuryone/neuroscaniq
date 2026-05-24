'use client';

import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium tracking-tight transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400/40 disabled:pointer-events-none disabled:opacity-40',
  {
    variants: {
      variant: {
        primary:
          'bg-signal-400 text-ink-950 hover:bg-signal-500 shadow-[0_0_24px_-4px_rgba(34,211,238,0.45)]',
        ghost: 'text-bone-200 hover:bg-ink-700/60 hover:text-bone-100',
        outline:
          'border border-ink-600 bg-ink-800/40 text-bone-100 hover:border-signal-400/40 hover:bg-ink-750/60',
        danger: 'bg-danger/90 text-ink-950 hover:bg-danger',
        link: 'text-signal-400 underline-offset-4 hover:underline',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        md: 'h-10 px-4',
        lg: 'h-12 px-6 text-base',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        className={cn(buttonVariants({ variant, size }), className)}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = 'Button';

export { buttonVariants };
