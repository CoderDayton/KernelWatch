import { createResource, Suspense, Show } from 'solid-js';
import { getDashboardStats, type DashboardStats } from '../lib/sidecar';

interface StatCardProps {
  label: string;
  value: number | string;
  variant?: 'default' | 'critical' | 'success';
}

function StatCard(props: StatCardProps) {
  const variantClasses = () => {
    switch (props.variant) {
      case 'critical':
        return 'border-critical/30 bg-critical/5';
      case 'success':
        return 'border-success/30 bg-success/5';
      default:
        return 'border-border bg-surface';
    }
  };

  return (
    <div class={`rounded-lg border p-4 ${variantClasses()}`}>
      <div class="text-text-muted text-sm">{props.label}</div>
      <div class="text-3xl font-bold mt-1 font-mono">{props.value}</div>
    </div>
  );
}

export default function Dashboard() {
  const [stats] = createResource<DashboardStats>(getDashboardStats);

  return (
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Dashboard</h1>
      
      <Suspense fallback={<div class="text-text-muted">Loading stats...</div>}>
        <Show when={stats()}>
          {(s) => (
            <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
              <StatCard label="Drivers Analyzed" value={s().drivers} />
              <StatCard label="Analysis Runs" value={s().analyses} />
              <StatCard 
                label="Vulnerabilities" 
                value={s().vulnerabilities}
                variant={s().vulnerabilities > 0 ? 'critical' : 'default'}
              />
              <StatCard label="LOLDrivers Hashes" value={s().loldrivers_hashes} />
              <StatCard 
                label="Critical Risk" 
                value={s().critical_risk}
                variant={s().critical_risk > 0 ? 'critical' : 'default'}
              />
            </div>
          )}
        </Show>
      </Suspense>

      <div class="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <div class="rounded-lg border border-border bg-surface p-4">
          <h2 class="text-lg font-semibold mb-4">Recent Activity</h2>
          <div class="text-text-muted text-sm">
            No recent activity. Start by analyzing a driver or syncing LOLDrivers.
          </div>
        </div>

        {/* Quick Actions */}
        <div class="rounded-lg border border-border bg-surface p-4">
          <h2 class="text-lg font-semibold mb-4">Quick Actions</h2>
          <div class="flex flex-col gap-2">
            <button class="px-4 py-2 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors text-left">
              📁 Analyze Driver File
            </button>
            <button class="px-4 py-2 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors text-left">
              🔄 Sync LOLDrivers Database
            </button>
            <button class="px-4 py-2 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors text-left">
              🔍 Search NVD for CVEs
            </button>
            <button class="px-4 py-2 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors text-left">
              📡 Start Monitoring
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
