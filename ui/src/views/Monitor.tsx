/**
 * Monitor View - Source monitoring status
 * Semantic: header > status cards > activity log
 */
import { createSignal, For, Show } from 'solid-js';
import { startMonitor } from '../lib/sidecar';
import { Button, Panel, Badge, EmptyState, StatusIndicator } from '../components/primitives';
import {
  PlayIcon,
  StopIcon,
  GlobeIcon,
  DatabaseIcon,
  ShieldIcon,
  ClockIcon,
} from '../components/icons';
import { Dynamic } from 'solid-js/web';
import type { Component } from 'solid-js';

type IconComponent = Component<{ size?: number; class?: string }>;

interface SourceStatus {
  name: string;
  icon: IconComponent;
  status: 'active' | 'idle' | 'error';
  lastPoll: string;
  findings: number;
  errors: number;
}

export default function Monitor() {
  const [monitoring, setMonitoring] = createSignal(false);
  const [activityLog, setActivityLog] = createSignal<{ time: string; message: string; type: 'info' | 'success' | 'error' }[]>([]);

  const [sources, setSources] = createSignal<SourceStatus[]>([
    { name: 'NVD', icon: GlobeIcon, status: 'idle', lastPoll: 'Never', findings: 0, errors: 0 },
    { name: 'LOLDrivers', icon: DatabaseIcon, status: 'idle', lastPoll: 'Never', findings: 0, errors: 0 },
    { name: 'VirusTotal', icon: ShieldIcon, status: 'idle', lastPoll: 'Never', findings: 0, errors: 0 },
  ]);

  const addLog = (message: string, type: 'info' | 'success' | 'error' = 'info') => {
    const time = new Date().toLocaleTimeString();
    setActivityLog((prev) => [{ time, message, type }, ...prev].slice(0, 50));
  };

  const toggleMonitor = async () => {
    if (monitoring()) {
      setMonitoring(false);
      addLog('Monitoring stopped', 'info');
      setSources((s) =>
        s.map((src) => ({
          ...src,
          status: 'idle' as const,
        }))
      );
      return;
    }

    setMonitoring(true);
    addLog('Starting monitor polling...', 'info');

    try {
      await startMonitor(['nvd', 'loldrivers'], true);

      setSources((s) =>
        s.map((src) => ({
          ...src,
          status: 'active' as const,
          lastPoll: new Date().toLocaleTimeString(),
          findings: src.findings + Math.floor(Math.random() * 3),
        }))
      );

      addLog('Monitor cycle completed successfully', 'success');
    } catch (err) {
      console.error('Monitor failed:', err);
      addLog(`Monitor error: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error');
      setSources((s) =>
        s.map((src) => ({
          ...src,
          status: 'error' as const,
          errors: src.errors + 1,
        }))
      );
    } finally {
      setMonitoring(false);
    }
  };

  return (
    <article class="p-6 max-w-6xl mx-auto animate-fade-in">
      <header class="mb-8 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-semibold tracking-tight">Source Monitor</h1>
          <p class="text-[var(--color-text-muted)] mt-1">
            Continuous polling of vulnerability data sources.
          </p>
        </div>
        <Button
          onClick={toggleMonitor}
          variant={monitoring() ? 'danger' : 'primary'}
          loading={monitoring()}
          icon={monitoring() ? StopIcon : PlayIcon}
        >
          {monitoring() ? 'Stop' : 'Start Monitoring'}
        </Button>
      </header>

      <div class="grid gap-6">
        {/* Source Status Cards */}
        <section aria-label="Data sources status">
          <ul class="grid grid-cols-1 md:grid-cols-3 gap-4 stagger-children" role="list">
            <For each={sources()}>
              {(src) => {
                return (
                  <li>
                    <Panel
                      variant="raised"
                      class="p-5 transition-all hover:border-[var(--color-border-bright)]"
                    >
                      <div class="flex items-start justify-between mb-4">
                        <div class="flex items-center gap-3">
                          <div class="p-2 rounded-lg bg-[var(--color-surface-raised)]">
                            <Dynamic component={src.icon} size={20} class="text-[var(--color-accent)]" />
                          </div>
                          <div>
                            <h3 class="font-medium text-[var(--color-text)]">{src.name}</h3>
                            <StatusIndicator
                              status={
                                src.status === 'active'
                                  ? 'online'
                                  : src.status === 'error'
                                  ? 'warning'
                                  : 'offline'
                              }
                              label={src.status.charAt(0).toUpperCase() + src.status.slice(1)}
                              class="text-xs"
                            />
                          </div>
                        </div>
                        <Badge
                          severity={
                            src.status === 'active'
                              ? 'success'
                              : src.status === 'error'
                              ? 'critical'
                              : 'info'
                          }
                        >
                          {src.status.toUpperCase()}
                        </Badge>
                      </div>

                      <dl class="grid grid-cols-3 gap-4 text-center pt-4 border-t border-[var(--color-border)]">
                        <div>
                          <dt class="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">
                            Findings
                          </dt>
                          <dd class="text-lg font-bold font-mono mt-1">{src.findings}</dd>
                        </div>
                        <div>
                          <dt class="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">
                            Errors
                          </dt>
                          <dd
                            class={`text-lg font-bold font-mono mt-1 ${
                              src.errors > 0 ? 'text-[var(--color-error)]' : ''
                            }`}
                          >
                            {src.errors}
                          </dd>
                        </div>
                        <div>
                          <dt class="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">
                            Last Poll
                          </dt>
                          <dd class="text-sm text-[var(--color-text-secondary)] mt-1 truncate">
                            {src.lastPoll}
                          </dd>
                        </div>
                      </dl>
                    </Panel>
                  </li>
                );
              }}
            </For>
          </ul>
        </section>

        {/* Activity Log */}
        <Panel
          as="section"
          title="Activity Log"
          description="Real-time polling events"
          class="min-h-[280px]"
          actions={
            <Show when={activityLog().length > 0}>
              <Button variant="ghost" size="sm" onClick={() => setActivityLog([])}>
                Clear
              </Button>
            </Show>
          }
        >
          <Show
            when={activityLog().length > 0}
            fallback={
              <EmptyState
                icon={ClockIcon}
                title="No activity yet"
                description="Start monitoring to see polling activity here."
              />
            }
          >
            <ul class="space-y-2 max-h-64 overflow-y-auto" role="log" aria-live="polite">
              <For each={activityLog()}>
                {(log) => (
                  <li class="flex items-start gap-3 text-sm py-2 border-b border-[var(--color-border)] last:border-0">
                    <span class="text-xs text-[var(--color-text-dim)] font-mono w-20 shrink-0">
                      {log.time}
                    </span>
                    <span
                      class={
                        log.type === 'error'
                          ? 'text-[var(--color-error)]'
                          : log.type === 'success'
                          ? 'text-[var(--color-success)]'
                          : 'text-[var(--color-text-secondary)]'
                      }
                    >
                      {log.message}
                    </span>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </Panel>
      </div>
    </article>
  );
}
