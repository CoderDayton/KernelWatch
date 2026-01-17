import { cva, type VariantProps } from 'class-variance-authority';
import { clsx, type ClassValue } from 'clsx';

/** Merge Tailwind classes with clsx */
export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

/** Button variants using CVA */
export const buttonVariants = cva(
  [
    'inline-flex items-center justify-center gap-2',
    'font-medium transition-colors',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-background)]',
    'disabled:pointer-events-none disabled:opacity-50',
  ],
  {
    variants: {
      variant: {
        primary: 'bg-[var(--color-accent)] text-[var(--color-background)] hover:bg-[var(--color-accent-bright)]',
        secondary: 'bg-[var(--color-surface-raised)] text-[var(--color-text)] hover:bg-[var(--color-border)]',
        ghost: 'bg-transparent text-[var(--color-text-muted)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text)]',
        danger: 'bg-[var(--color-error)]/10 text-[var(--color-error)] hover:bg-[var(--color-error)]/20',
      },
      size: {
        sm: 'h-8 px-3 text-sm rounded',
        md: 'h-10 px-4 text-sm rounded-md',
        lg: 'h-12 px-6 text-base rounded-lg',
        icon: 'h-10 w-10 rounded-md',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  }
);

export type ButtonVariants = VariantProps<typeof buttonVariants>;

/** Input variants */
export const inputVariants = cva(
  [
    'w-full bg-[var(--color-surface)] border border-[var(--color-border)]',
    'text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]',
    'focus-visible:outline-none focus-visible:border-[var(--color-accent)] focus-visible:ring-1 focus-visible:ring-[var(--color-accent)]',
    'disabled:opacity-50 disabled:cursor-not-allowed',
    'transition-colors',
  ],
  {
    variants: {
      size: {
        sm: 'h-8 px-3 text-sm rounded',
        md: 'h-10 px-4 text-sm rounded-md',
        lg: 'h-12 px-4 text-base rounded-lg',
      },
    },
    defaultVariants: {
      size: 'md',
    },
  }
);

/** Badge/Tag variants for risk levels and status */
export const badgeVariants = cva(
  'inline-flex items-center px-2 py-0.5 rounded border text-xs font-mono',
  {
    variants: {
      severity: {
        critical: 'bg-[var(--color-critical)]/15 text-[var(--color-critical)] border-[var(--color-critical)]/40',
        high: 'bg-[var(--color-high)]/15 text-[var(--color-high)] border-[var(--color-high)]/40',
        medium: 'bg-[var(--color-medium)]/15 text-[var(--color-medium)] border-[var(--color-medium)]/40',
        low: 'bg-[var(--color-low)]/15 text-[var(--color-low)] border-[var(--color-low)]/40',
        info: 'bg-[var(--color-info)]/15 text-[var(--color-info)] border-[var(--color-info)]/40',
        success: 'bg-[var(--color-success)]/15 text-[var(--color-success)] border-[var(--color-success)]/40',
      },
    },
    defaultVariants: {
      severity: 'info',
    },
  }
);

export type BadgeVariants = VariantProps<typeof badgeVariants>;

/** Card/Panel variants */
export const panelVariants = cva(
  'rounded-lg border p-5',
  {
    variants: {
      variant: {
        default: 'bg-[var(--color-surface)] border-[var(--color-border)]',
        raised: 'bg-[var(--color-surface-raised)] border-[var(--color-border)]',
        ghost: 'bg-transparent border-transparent p-0',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);
