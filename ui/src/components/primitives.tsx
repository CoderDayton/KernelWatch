/**
 * Semantic UI primitives with full A11y support
 */
import { type JSX, type ParentProps, splitProps, Show } from 'solid-js';
import { buttonVariants, inputVariants, badgeVariants, panelVariants, cn, type ButtonVariants, type BadgeVariants } from '../lib/styles';

/* ============================================================================
 * BUTTON
 * ========================================================================== */

interface ButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement>, ButtonVariants {
  loading?: boolean;
}

export function Button(props: ButtonProps) {
  const [local, variants, rest] = splitProps(
    props,
    ['class', 'children', 'loading', 'disabled'],
    ['variant', 'size']
  );

  return (
    <button
      class={cn(buttonVariants(variants), local.class)}
      disabled={local.disabled || local.loading}
      aria-busy={local.loading}
      {...rest}
    >
      <Show when={local.loading}>
        <span class="animate-spin" aria-hidden="true">⟳</span>
      </Show>
      {local.children}
    </button>
  );
}

/* ============================================================================
 * INPUT
 * ========================================================================== */

interface InputProps extends JSX.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function Input(props: InputProps) {
  const [local, rest] = splitProps(props, ['class', 'label', 'error', 'id']);
  const inputId = local.id || `input-${Math.random().toString(36).slice(2, 9)}`;

  return (
    <div class="flex flex-col gap-1.5">
      <Show when={local.label}>
        <label for={inputId} class="text-sm text-[var(--color-text-muted)]">
          {local.label}
        </label>
      </Show>
      <input
        id={inputId}
        class={cn(inputVariants(), local.class)}
        aria-invalid={!!local.error}
        aria-describedby={local.error ? `${inputId}-error` : undefined}
        {...rest}
      />
      <Show when={local.error}>
        <p id={`${inputId}-error`} class="text-sm text-[var(--color-error)]" role="alert">
          {local.error}
        </p>
      </Show>
    </div>
  );
}

/* ============================================================================
 * BADGE
 * ========================================================================== */

interface BadgeProps extends BadgeVariants {
  class?: string;
  children: JSX.Element;
}

export function Badge(props: BadgeProps) {
  const [local, variants] = splitProps(props, ['class', 'children']);
  
  return (
    <span class={cn(badgeVariants(variants), local.class)}>
      {local.children}
    </span>
  );
}

/* ============================================================================
 * PANEL (Card/Section wrapper)
 * ========================================================================== */

interface PanelProps extends ParentProps {
  as?: 'section' | 'article' | 'aside' | 'div';
  variant?: 'default' | 'raised' | 'ghost';
  class?: string;
  'aria-label'?: string;
  'aria-labelledby'?: string;
}

export function Panel(props: PanelProps) {
  const [local, rest] = splitProps(props, ['as', 'variant', 'class', 'children']);
  const Tag = local.as || 'section';

  return (
    <Tag class={cn(panelVariants({ variant: local.variant }), local.class)} {...rest}>
      {local.children}
    </Tag>
  );
}

/* ============================================================================
 * SKELETON (Loading placeholder)
 * ========================================================================== */

interface SkeletonProps {
  class?: string;
  height?: string;
  width?: string;
}

export function Skeleton(props: SkeletonProps) {
  return (
    <span
      class={cn(
        'block animate-pulse bg-[var(--color-border)] rounded',
        props.class
      )}
      style={{
        height: props.height || '1rem',
        width: props.width || '100%',
      }}
      aria-hidden="true"
    />
  );
}

/* ============================================================================
 * STAT CARD (Dashboard metric)
 * ========================================================================== */

interface StatCardProps {
  label: string;
  value: number | string;
  severity?: BadgeVariants['severity'];
  loading?: boolean;
}

export function StatCard(props: StatCardProps) {
  const borderClass = () => {
    if (!props.severity || props.severity === 'info') return '';
    return `border-[var(--color-${props.severity})]/30`;
  };

  return (
    <article 
      class={cn('rounded-lg border bg-[var(--color-surface)] p-4', borderClass())}
      aria-label={`${props.label}: ${props.value}`}
    >
      <p class="text-[var(--color-text-muted)] text-sm">{props.label}</p>
      <Show 
        when={!props.loading} 
        fallback={<Skeleton height="2rem" width="4rem" class="mt-1" />}
      >
        <p class="text-3xl font-bold mt-1 font-mono">{props.value}</p>
      </Show>
    </article>
  );
}

/* ============================================================================
 * EMPTY STATE
 * ========================================================================== */

interface EmptyStateProps extends ParentProps {
  icon?: string;
  title: string;
  description?: string;
}

export function EmptyState(props: EmptyStateProps) {
  return (
    <section 
      class="flex flex-col items-center justify-center py-12 text-center"
      aria-label={props.title}
    >
      <Show when={props.icon}>
        <span class="text-4xl mb-4" aria-hidden="true">{props.icon}</span>
      </Show>
      <h3 class="text-lg font-medium text-[var(--color-text)]">{props.title}</h3>
      <Show when={props.description}>
        <p class="text-sm text-[var(--color-text-muted)] mt-1 max-w-md">
          {props.description}
        </p>
      </Show>
      <Show when={props.children}>
        <footer class="mt-4">{props.children}</footer>
      </Show>
    </section>
  );
}

/* ============================================================================
 * DATA TABLE (Semantic table with loading states)
 * ========================================================================== */

interface Column<T> {
  key: keyof T | string;
  header: string;
  render?: (item: T) => JSX.Element;
  class?: string;
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  loading?: boolean;
  emptyMessage?: string;
  'aria-label': string;
  rowKey: (item: T) => string;
}

export function DataTable<T>(props: DataTableProps<T>) {
  if (props.loading) {
    return (
      <div class="space-y-2" role="status" aria-label="Loading data">
        {[1, 2, 3].map(() => <Skeleton height="3rem" />)}
      </div>
    );
  }

  if (props.data.length === 0) {
    return (
      <EmptyState 
        icon="📭" 
        title={props.emptyMessage || 'No data'} 
      />
    );
  }

  return (
    <table class="w-full text-sm" aria-label={props['aria-label']}>
      <thead>
        <tr class="border-b border-[var(--color-border)]">
          {props.columns.map((col) => (
            <th 
              class={cn('px-4 py-3 text-left font-medium text-[var(--color-text-muted)]', col.class)}
              scope="col"
            >
              {col.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {props.data.map((item) => (
          <tr 
            class="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-raised)] transition-colors"
          >
            {props.columns.map((col) => (
              <td class={cn('px-4 py-3', col.class)}>
                {col.render 
                  ? col.render(item) 
                  : String((item as Record<string, unknown>)[col.key as string] ?? '-')
                }
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
