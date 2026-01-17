/**
 * Semantic UI primitives with full A11y support
 */
import { type JSX, type ParentProps, type Component, splitProps, Show, For } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import { buttonVariants, inputVariants, badgeVariants, panelVariants, cn, type ButtonVariants, type BadgeVariants } from '../lib/styles';
import { LoaderIcon, InfoIcon, AlertCircleIcon } from './icons';

type IconComponent = Component<{ size?: number; class?: string }>;

/* ============================================================================
 * BUTTON
 * ========================================================================== */

interface ButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement>, ButtonVariants {
  loading?: boolean;
  icon?: IconComponent;
  iconPosition?: 'left' | 'right';
}

export function Button(props: ButtonProps) {
  const [local, variants, rest] = splitProps(
    props,
    ['class', 'children', 'loading', 'disabled', 'icon', 'iconPosition'],
    ['variant', 'size']
  );

  const iconLeft = local.iconPosition !== 'right';

  return (
    <button
      class={cn(buttonVariants(variants), 'inline-flex items-center justify-center gap-2', local.class)}
      disabled={local.disabled || local.loading}
      aria-busy={local.loading}
      {...rest}
    >
      <Show when={local.loading}>
        <LoaderIcon size={16} class="animate-spin" />
      </Show>
      <Show when={!local.loading && local.icon && iconLeft}>
        <Dynamic component={local.icon} size={16} />
      </Show>
      {local.children}
      <Show when={!local.loading && local.icon && !iconLeft}>
        <Dynamic component={local.icon} size={16} />
      </Show>
    </button>
  );
}

/* ============================================================================
 * INPUT
 * ========================================================================== */

interface InputProps extends JSX.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  icon?: IconComponent;
}

export function Input(props: InputProps) {
  const [local, rest] = splitProps(props, ['class', 'label', 'error', 'hint', 'id', 'icon']);
  const inputId = local.id || `input-${Math.random().toString(36).slice(2, 9)}`;

  return (
    <div class="flex flex-col gap-1.5">
      <Show when={local.label}>
        <label for={inputId} class="text-sm font-medium text-[var(--color-text-secondary)]">
          {local.label}
        </label>
      </Show>
      <div class="relative">
        <Show when={local.icon}>
          <span class="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]">
            <Dynamic component={local.icon} size={16} />
          </span>
        </Show>
        <input
          id={inputId}
          class={cn(
            inputVariants(),
            local.icon && 'pl-10',
            local.error && 'border-[var(--color-error)] focus:ring-[var(--color-error)]',
            local.class
          )}
          aria-invalid={!!local.error}
          aria-describedby={local.error ? `${inputId}-error` : local.hint ? `${inputId}-hint` : undefined}
          {...rest}
        />
      </div>
      <Show when={local.hint && !local.error}>
        <p id={`${inputId}-hint`} class="text-xs text-[var(--color-text-muted)]">
          {local.hint}
        </p>
      </Show>
      <Show when={local.error}>
        <p id={`${inputId}-error`} class="text-xs text-[var(--color-error)] flex items-center gap-1" role="alert">
          <AlertCircleIcon size={12} />
          {local.error}
        </p>
      </Show>
    </div>
  );
}

/* ============================================================================
 * TEXTAREA
 * ========================================================================== */

interface TextareaProps extends JSX.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export function Textarea(props: TextareaProps) {
  const [local, rest] = splitProps(props, ['class', 'label', 'error', 'hint', 'id']);
  const inputId = local.id || `textarea-${Math.random().toString(36).slice(2, 9)}`;

  return (
    <div class="flex flex-col gap-1.5">
      <Show when={local.label}>
        <label for={inputId} class="text-sm font-medium text-[var(--color-text-secondary)]">
          {local.label}
        </label>
      </Show>
      <textarea
        id={inputId}
        class={cn(
          inputVariants(),
          'min-h-[100px] resize-y',
          local.error && 'border-[var(--color-error)] focus:ring-[var(--color-error)]',
          local.class
        )}
        aria-invalid={!!local.error}
        aria-describedby={local.error ? `${inputId}-error` : local.hint ? `${inputId}-hint` : undefined}
        {...rest}
      />
      <Show when={local.hint && !local.error}>
        <p id={`${inputId}-hint`} class="text-xs text-[var(--color-text-muted)]">
          {local.hint}
        </p>
      </Show>
      <Show when={local.error}>
        <p id={`${inputId}-error`} class="text-xs text-[var(--color-error)] flex items-center gap-1" role="alert">
          <AlertCircleIcon size={12} />
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
  icon?: IconComponent;
}

export function Badge(props: BadgeProps) {
  const [local, variants] = splitProps(props, ['class', 'children', 'icon']);

  return (
    <span class={cn(badgeVariants(variants), 'inline-flex items-center gap-1', local.class)}>
      <Show when={local.icon}>
        <Dynamic component={local.icon} size={12} />
      </Show>
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
  title?: string;
  description?: string;
  actions?: JSX.Element;
  'aria-label'?: string;
  'aria-labelledby'?: string;
}

export function Panel(props: PanelProps) {
  const [local, rest] = splitProps(props, ['as', 'variant', 'class', 'children', 'title', 'description', 'actions']);
  const Tag = local.as || 'section';
  const hasHeader = local.title || local.description || local.actions;

  return (
    <Tag class={cn(panelVariants({ variant: local.variant }), local.class)} {...rest}>
      <Show when={hasHeader}>
        <header class="flex items-start justify-between gap-4 mb-4">
          <div>
            <Show when={local.title}>
              <h3 class="text-base font-semibold text-[var(--color-text)]">{local.title}</h3>
            </Show>
            <Show when={local.description}>
              <p class="text-sm text-[var(--color-text-muted)] mt-0.5">{local.description}</p>
            </Show>
          </div>
          <Show when={local.actions}>
            <div class="flex items-center gap-2 shrink-0">
              {local.actions}
            </div>
          </Show>
        </header>
      </Show>
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
        'block animate-pulse bg-[var(--color-surface-hover)] rounded-md',
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
  icon?: IconComponent;
  severity?: BadgeVariants['severity'];
  loading?: boolean;
  trend?: { value: number; label: string };
}

export function StatCard(props: StatCardProps) {
  const severityColors: Record<string, string> = {
    critical: 'border-l-[var(--color-critical)] bg-[var(--color-critical-bg)]',
    high: 'border-l-[var(--color-high)] bg-[var(--color-high-bg)]',
    medium: 'border-l-[var(--color-medium)] bg-[var(--color-medium-bg)]',
    low: 'border-l-[var(--color-low)] bg-[var(--color-low-bg)]',
    success: 'border-l-[var(--color-success)] bg-[var(--color-success-bg)]',
  };

  const cardClass = () => {
    if (props.severity && severityColors[props.severity]) {
      return `border-l-4 ${severityColors[props.severity]}`;
    }
    return 'border border-[var(--color-border)] bg-[var(--color-surface)]';
  };

  return (
    <article
      class={cn(
        'rounded-lg p-4 transition-all duration-200 hover:shadow-md',
        cardClass()
      )}
      aria-label={`${props.label}: ${props.value}`}
    >
      <div class="flex items-start justify-between gap-3">
        <div class="flex-1 min-w-0">
          <p class="text-sm text-[var(--color-text-muted)] truncate">{props.label}</p>
          <Show
            when={!props.loading}
            fallback={<Skeleton height="2.25rem" width="5rem" class="mt-2" />}
          >
            <p class="text-3xl font-bold mt-1 font-mono tracking-tight text-[var(--color-text)]">
              {props.value}
            </p>
          </Show>
          <Show when={props.trend}>
            <p class={cn(
              'text-xs mt-2 flex items-center gap-1',
              props.trend!.value >= 0 ? 'text-[var(--color-success)]' : 'text-[var(--color-error)]'
            )}>
              <span>{props.trend!.value >= 0 ? '↑' : '↓'}</span>
              <span>{Math.abs(props.trend!.value)}% {props.trend!.label}</span>
            </p>
          </Show>
        </div>
        <Show when={props.icon}>
          <div class="p-2 rounded-lg bg-[var(--color-surface-raised)] text-[var(--color-text-muted)]">
            <Dynamic component={props.icon} size={20} />
          </div>
        </Show>
      </div>
    </article>
  );
}

/* ============================================================================
 * EMPTY STATE
 * ========================================================================== */

interface EmptyStateProps extends ParentProps {
  icon?: IconComponent;
  title: string;
  description?: string;
}

export function EmptyState(props: EmptyStateProps) {
  return (
    <section
      class="flex flex-col items-center justify-center py-12 px-6 text-center"
      aria-label={props.title}
    >
      <div class="w-12 h-12 rounded-full bg-[var(--color-surface-raised)] flex items-center justify-center mb-4">
        <Dynamic component={props.icon || InfoIcon} size={24} class="text-[var(--color-text-muted)]" />
      </div>
      <h3 class="text-base font-medium text-[var(--color-text)]">{props.title}</h3>
      <Show when={props.description}>
        <p class="text-sm text-[var(--color-text-muted)] mt-1 max-w-sm">
          {props.description}
        </p>
      </Show>
      <Show when={props.children}>
        <footer class="mt-6">{props.children}</footer>
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
  emptyIcon?: IconComponent;
  'aria-label': string;
  rowKey: (item: T) => string;
  onRowClick?: (item: T) => void;
}

export function DataTable<T>(props: DataTableProps<T>) {
  if (props.loading) {
    return (
      <div class="space-y-2" role="status" aria-label="Loading data">
        <For each={[1, 2, 3, 4, 5]}>
          {() => <Skeleton height="3rem" />}
        </For>
      </div>
    );
  }

  if (props.data.length === 0) {
    return (
      <EmptyState
        icon={props.emptyIcon}
        title={props.emptyMessage || 'No data found'}
        description="Try adjusting your search or filters"
      />
    );
  }

  return (
    <div class="overflow-x-auto rounded-lg border border-[var(--color-border)]">
      <table class="w-full text-sm" aria-label={props['aria-label']}>
        <thead class="bg-[var(--color-surface)]">
          <tr>
            <For each={props.columns}>
              {(col) => (
                <th
                  class={cn(
                    'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)]',
                    col.class
                  )}
                  scope="col"
                >
                  {col.header}
                </th>
              )}
            </For>
          </tr>
        </thead>
        <tbody class="divide-y divide-[var(--color-border)]">
          <For each={props.data}>
            {(item) => (
              <tr
                class={cn(
                  'bg-[var(--color-background)] transition-colors',
                  props.onRowClick && 'cursor-pointer hover:bg-[var(--color-surface-hover)]'
                )}
                onClick={() => props.onRowClick?.(item)}
                tabIndex={props.onRowClick ? 0 : undefined}
                onKeyDown={(e) => {
                  if (props.onRowClick && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    props.onRowClick(item);
                  }
                }}
              >
                <For each={props.columns}>
                  {(col) => (
                    <td class={cn('px-4 py-3 text-[var(--color-text)]', col.class)}>
                      {col.render
                        ? col.render(item)
                        : String((item as Record<string, unknown>)[col.key as string] ?? '-')}
                    </td>
                  )}
                </For>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

/* ============================================================================
 * TABS
 * ========================================================================== */

interface Tab {
  id: string;
  label: string;
  icon?: IconComponent;
}

interface TabsProps {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
  class?: string;
}

export function Tabs(props: TabsProps) {
  return (
    <div class={cn('border-b border-[var(--color-border)]', props.class)} role="tablist">
      <div class="flex gap-1 -mb-px">
        <For each={props.tabs}>
          {(tab) => {
            const isActive = () => props.active === tab.id;
            return (
              <button
                role="tab"
                aria-selected={isActive()}
                aria-controls={`tabpanel-${tab.id}`}
                id={`tab-${tab.id}`}
                onClick={() => props.onChange(tab.id)}
                class={cn(
                  'px-4 py-2.5 text-sm font-medium transition-colors flex items-center gap-2 border-b-2 -mb-px',
                  isActive()
                    ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                    : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-border-bright)]'
                )}
              >
                <Show when={tab.icon}>
                  <Dynamic component={tab.icon} size={16} />
                </Show>
                {tab.label}
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
}

interface TabPanelProps extends ParentProps {
  id: string;
  active: string;
}

export function TabPanel(props: TabPanelProps) {
  return (
    <Show when={props.active === props.id}>
      <div
        role="tabpanel"
        id={`tabpanel-${props.id}`}
        aria-labelledby={`tab-${props.id}`}
        class="animate-fade-in"
      >
        {props.children}
      </div>
    </Show>
  );
}

/* ============================================================================
 * PROGRESS BAR
 * ========================================================================== */

interface ProgressProps {
  value: number;
  max?: number;
  label?: string;
  showValue?: boolean;
  severity?: 'default' | 'success' | 'warning' | 'error';
  class?: string;
}

export function Progress(props: ProgressProps) {
  const max = props.max ?? 100;
  const percentage = () => Math.min(100, Math.max(0, (props.value / max) * 100));

  const severityColors: Record<string, string> = {
    default: 'bg-[var(--color-accent)]',
    success: 'bg-[var(--color-success)]',
    warning: 'bg-[var(--color-warning)]',
    error: 'bg-[var(--color-error)]',
  };

  return (
    <div class={cn('space-y-1.5', props.class)}>
      <Show when={props.label || props.showValue}>
        <div class="flex justify-between text-xs">
          <Show when={props.label}>
            <span class="text-[var(--color-text-muted)]">{props.label}</span>
          </Show>
          <Show when={props.showValue}>
            <span class="text-[var(--color-text-secondary)] font-mono">
              {props.value}/{max}
            </span>
          </Show>
        </div>
      </Show>
      <div
        class="h-2 bg-[var(--color-surface-raised)] rounded-full overflow-hidden"
        role="progressbar"
        aria-valuenow={props.value}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={props.label}
      >
        <div
          class={cn('h-full rounded-full transition-all duration-300', severityColors[props.severity ?? 'default'])}
          style={{ width: `${percentage()}%` }}
        />
      </div>
    </div>
  );
}

/* ============================================================================
 * STATUS INDICATOR
 * ========================================================================== */

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'warning' | 'loading';
  label?: string;
  class?: string;
}

export function StatusIndicator(props: StatusIndicatorProps) {
  const statusConfig = {
    online: { color: 'bg-[var(--color-success)]', label: 'Online' },
    offline: { color: 'bg-[var(--color-text-dim)]', label: 'Offline' },
    warning: { color: 'bg-[var(--color-warning)]', label: 'Warning' },
    loading: { color: 'bg-[var(--color-accent)]', label: 'Loading' },
  };

  const config = statusConfig[props.status];

  return (
    <span class={cn('inline-flex items-center gap-2 text-sm', props.class)}>
      <span
        class={cn(
          'w-2 h-2 rounded-full',
          config.color,
          props.status === 'loading' && 'animate-pulse'
        )}
      />
      <span class="text-[var(--color-text-secondary)]">
        {props.label ?? config.label}
      </span>
    </span>
  );
}
