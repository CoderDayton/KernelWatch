/**
 * Dashboard View - Overview and statistics
 * Semantic: section > article structure, proper headings, ARIA labels
 */
import { createResource, Suspense, Show, For } from 'solid-js';
import { getDashboardStats, type DashboardStats } from '../lib/sidecar';
import { Panel, StatCard, EmptyState, Skeleton } from '../components/primitives';
import { cn } from '../lib/styles';

const QUICK_ACTIONS = [
  { id: 'analyze', label: 'Analyze Driver', icon: '📁', desc: 'Analyze a driver file for vulnerabilities' },
  { id: 'sync', label: 'Sync LOLDrivers', icon: '🔄', desc: 'Update the LOLDrivers hash database' },
  { id: 'search', label: 'Search NVD', icon: '🔍', desc: 'Search for driver-related CVEs' },
  { id: 'monitor', label: 'Start Monitor', icon: '📡', desc: 'Begin monitoring sources' },
] as const;

function StatsGrid(props: { stats: DashboardStats }) {
  const items = () => [
    { label: 'Drivers Analyzed', value: props.stats.drivers },
    { label: 'Analysis Runs', value: props.stats.analyses },
    { label: 'Vulnerabilities', value: props.stats.vulnerabilities, severity: props.stats.vulnerabilities > 0 ? 'critical' as const : undefined },
    { label: 'LOLDrivers Hashes', value: props.stats.loldrivers_hashes },
    { label: 'Critical Risk', value: props.stats.critical_risk, severity: props.stats.critical_risk > 0 ? 'critical' as const : undefined },
  ];

  return (
    <section aria-label="Statistics overview">
      <ul class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4" role="list">
        <For each={items()}>
          {(stat) => (
            <li><StatCard label={stat.label} value={stat.value} severity={stat.severity} /></li>
          )}
        </For>
      </ul>
    </section>
  );
}

function QuickActions(props: { onAction: (id: string) => void }) {
  return (
    <Panel as="section" class="p-4" aria-labelledby="qa-heading">
      <h2 id="qa-heading" class="text-lg font-semibold mb-4">Quick Actions</h2>
      <nav aria-label="Quick actions">
        <ul class="flex flex-col gap-2" role="list">
          <For each={QUICK_ACTIONS}>
            {(a) => (
              <li>
                <button
                  onClick={() => props.onAction(a.id)}
                  class={cn(
                    'w-full px-4 py-3 rounded text-left flex items-center gap-3',
                    'bg-[var(--color-accent)]/10 text-[var(--color-accent)]',
                    'hover:bg-[var(--color-accent)]/20 transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]'
                  )}
                  aria-describedby={`${a.id}-d`}
                >
                  <span aria-hidden="true" class="text-xl">{a.icon}</span>
                  <span class="flex flex-col">
                    <span class="font-medium">{a.label}</span>
                    <span id={`${a.id}-d`} class="text-xs text-[var(--color-text-muted)]">{a.desc}</span>
                  </span>
                </button>
              </li>
            )}
          </For>
        </ul>
      </nav>
    </Panel>
  );
}

function RecentActivity() {
  return (
    <Panel as="section" class="p-4" aria-labelledby="activity-heading">
      <h2 id="activity-heading" class="text-lg font-semibold mb-4">Recent Activity</h2>
      <EmptyState icon="📋" title="No recent activity" description="Start by analyzing a driver or syncing LOLDrivers." />
    </Panel>
  );
}

export default function Dashboard() {
  const [stats] = createResource<DashboardStats>(getDashboardStats);
  const handleAction = (id: string) => console.log('Action:', id);

  return (
    <article class="p-6 space-y-8">
      <header>
        <h1 class="text-2xl font-bold">Dashboard</h1>
        <p class="text-[var(--color-text-muted)] mt-1">Overview of your driver research activity</p>
      </header>

      <Suspense fallback={
        <section aria-label="Loading" aria-busy="true">
          <ul class="grid grid-cols-5 gap-4" role="list">
            {[1,2,3,4,5].map(() => <li><Skeleton height="5rem" /></li>)}
          </ul>
        </section>
      }>
        <Show when={stats()}>{(s) => <StatsGrid stats={s()} />}</Show>
      </Suspense>

      <section class="grid grid-cols-1 lg:grid-cols-2 gap-6" aria-label="Dashboard panels">
        <RecentActivity />
        <QuickActions onAction={handleAction} />
      </section>
    </article>
  );
}
