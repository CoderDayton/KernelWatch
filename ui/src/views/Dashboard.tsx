/**
 * Dashboard View - Overview and statistics
 * Semantic: section > article structure, proper headings, ARIA labels
 */
import { createResource, Suspense, Show, For } from 'solid-js';
import { getDashboardStats, type DashboardStats } from '../lib/sidecar';
import { Panel, StatCard, EmptyState, Skeleton, Button } from '../components/primitives';
import {
  DatabaseIcon,
  ActivityIcon,
  BugIcon,
  HashIcon,
  ShieldAlertIcon,
  FolderIcon,
  RefreshIcon,
  SearchIcon,
  MonitorIcon,
  ClockIcon,
  ChevronRightIcon,
} from '../components/icons';
import { cn } from '../lib/styles';

const QUICK_ACTIONS = [
  {
    id: 'analyze',
    label: 'Analyze Driver',
    icon: FolderIcon,
    desc: 'Scan a driver file for vulnerabilities',
    color: 'var(--color-accent)',
  },
  {
    id: 'sync',
    label: 'Sync LOLDrivers',
    icon: RefreshIcon,
    desc: 'Update the LOLDrivers database',
    color: 'var(--color-success)',
  },
  {
    id: 'search',
    label: 'Search NVD',
    icon: SearchIcon,
    desc: 'Find driver-related CVEs',
    color: 'var(--color-high)',
  },
  {
    id: 'monitor',
    label: 'Start Monitor',
    icon: MonitorIcon,
    desc: 'Begin real-time monitoring',
    color: 'var(--color-medium)',
  },
] as const;

function StatsGrid(props: { stats: DashboardStats }) {
  const items = () => [
    {
      label: 'Drivers Analyzed',
      value: props.stats.drivers,
      icon: DatabaseIcon,
    },
    {
      label: 'Analysis Runs',
      value: props.stats.analyses,
      icon: ActivityIcon,
    },
    {
      label: 'Vulnerabilities',
      value: props.stats.vulnerabilities,
      icon: BugIcon,
      severity: props.stats.vulnerabilities > 0 ? ('critical' as const) : undefined,
    },
    {
      label: 'LOLDrivers Hashes',
      value: props.stats.loldrivers_hashes,
      icon: HashIcon,
    },
    {
      label: 'Critical Risk',
      value: props.stats.critical_risk,
      icon: ShieldAlertIcon,
      severity: props.stats.critical_risk > 0 ? ('critical' as const) : undefined,
    },
  ];

  return (
    <section aria-label="Statistics overview" class="stagger-children">
      <ul class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" role="list">
        <For each={items()}>
          {(stat) => (
            <li>
              <StatCard
                label={stat.label}
                value={stat.value}
                icon={stat.icon}
                severity={stat.severity}
              />
            </li>
          )}
        </For>
      </ul>
    </section>
  );
}

function QuickActions(props: { onAction: (id: string) => void }) {
  return (
    <Panel
      as="section"
      title="Quick Actions"
      description="Common tasks to get started"
      class="h-full"
    >
      <nav aria-label="Quick actions">
        <ul class="flex flex-col gap-2" role="list">
          <For each={QUICK_ACTIONS}>
            {(action) => {
              const Icon = action.icon;
              return (
                <li>
                  <button
                    onClick={() => props.onAction(action.id)}
                    class={cn(
                      'w-full px-4 py-3 rounded-lg text-left flex items-center gap-4 group',
                      'bg-[var(--color-surface-raised)] border border-[var(--color-border)]',
                      'hover:border-[var(--color-border-bright)] hover:bg-[var(--color-surface-hover)]',
                      'transition-all duration-150',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]'
                    )}
                    aria-describedby={`${action.id}-desc`}
                  >
                    <span
                      class="p-2 rounded-lg transition-colors"
                      style={{ background: `color-mix(in srgb, ${action.color} 15%, transparent)` }}
                    >
                      <Icon size={20} style={{ color: action.color }} />
                    </span>
                    <span class="flex flex-col flex-1 min-w-0">
                      <span class="font-medium text-[var(--color-text)]">{action.label}</span>
                      <span
                        id={`${action.id}-desc`}
                        class="text-xs text-[var(--color-text-muted)] truncate"
                      >
                        {action.desc}
                      </span>
                    </span>
                    <ChevronRightIcon
                      size={16}
                      class="text-[var(--color-text-dim)] group-hover:text-[var(--color-text-muted)] transition-colors"
                    />
                  </button>
                </li>
              );
            }}
          </For>
        </ul>
      </nav>
    </Panel>
  );
}

function RecentActivity() {
  // TODO: Implement actual activity tracking
  const activities: { id: string; action: string; target: string; time: string }[] = [];

  return (
    <Panel
      as="section"
      title="Recent Activity"
      description="Your latest actions and findings"
      actions={
        <Button variant="ghost" size="sm">
          View All
        </Button>
      }
      class="h-full"
    >
      <Show
        when={activities.length > 0}
        fallback={
          <EmptyState
            icon={ClockIcon}
            title="No recent activity"
            description="Start by analyzing a driver or syncing the LOLDrivers database."
          />
        }
      >
        <ul class="divide-y divide-[var(--color-border)]" role="list">
          <For each={activities}>
            {(activity) => (
              <li class="py-3 flex items-center gap-3">
                <span class="text-sm text-[var(--color-text)]">{activity.action}</span>
                <code class="text-xs text-[var(--color-accent)]">{activity.target}</code>
                <span class="text-xs text-[var(--color-text-dim)] ml-auto">{activity.time}</span>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </Panel>
  );
}

function StatsLoadingSkeleton() {
  return (
    <section aria-label="Loading statistics" aria-busy="true">
      <ul class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" role="list">
        <For each={[1, 2, 3, 4, 5]}>
          {() => (
            <li>
              <div class="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
                <Skeleton height="0.875rem" width="60%" />
                <Skeleton height="2.25rem" width="40%" class="mt-3" />
              </div>
            </li>
          )}
        </For>
      </ul>
    </section>
  );
}

export default function Dashboard() {
  const [stats] = createResource<DashboardStats>(getDashboardStats);

  const handleAction = (id: string) => {
    // TODO: Implement navigation to respective views
    console.log('Quick action:', id);
  };

  return (
    <article class="p-6 space-y-8 animate-fade-in">
      <header>
        <h1 class="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Overview of your driver security research
        </p>
      </header>

      <Suspense fallback={<StatsLoadingSkeleton />}>
        <Show when={stats()}>{(s) => <StatsGrid stats={s()} />}</Show>
      </Suspense>

      <section
        class="grid grid-cols-1 lg:grid-cols-2 gap-6"
        aria-label="Dashboard panels"
      >
        <RecentActivity />
        <QuickActions onAction={handleAction} />
      </section>
    </article>
  );
}
