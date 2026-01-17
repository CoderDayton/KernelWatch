/**
 * Monitor View - Source monitoring status
 */
import { createSignal, For } from 'solid-js';
import { startMonitor } from '../lib/sidecar';
import { Button, Panel, Badge, EmptyState } from '../components/primitives';

interface SourceStatus {
  name: string;
  status: 'active' | 'idle' | 'error';
  lastPoll: string;
  findings: number;
  errors: number;
}

export default function Monitor() {
  const [monitoring, setMonitoring] = createSignal(false);
  
  // Mock data for now - real implementation would need websocket/event stream
  const [sources, setSources] = createSignal<SourceStatus[]>([
    { name: 'NVD', status: 'idle', lastPoll: 'Never', findings: 0, errors: 0 },
    { name: 'LOLDrivers', status: 'idle', lastPoll: 'Never', findings: 0, errors: 0 },
    { name: 'VirusTotal', status: 'idle', lastPoll: 'Never', findings: 0, errors: 0 },
  ]);

  const toggleMonitor = async () => {
    if (monitoring()) {
      // Stop logic would go here
      setMonitoring(false);
      return;
    }

    setMonitoring(true);
    try {
      // In a real app, this would spawn a background process we can detach from
      // For now, we'll just run 'once' mode to demonstrate connectivity
      await startMonitor(['nvd', 'loldrivers'], true);
      
      // Update mock status
      setSources(s => s.map(src => ({
        ...src,
        status: 'active',
        lastPoll: 'Just now',
        findings: Math.floor(Math.random() * 5)
      })));
    } catch (err) {
      console.error('Monitor failed:', err);
    } finally {
      setMonitoring(false);
    }
  };

  return (
    <article class="p-6 max-w-5xl mx-auto">
      <header class="mb-8 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold">Source Monitor</h1>
          <p class="text-[var(--color-text-muted)] mt-1">
            Continuous polling of vulnerability sources.
          </p>
        </div>
        <Button 
          onClick={toggleMonitor} 
          variant={monitoring() ? 'danger' : 'primary'}
          loading={monitoring()}
        >
          {monitoring() ? 'Stop Monitoring' : 'Start Monitoring'}
        </Button>
      </header>

      <div class="grid gap-6">
        <Panel aria-label="Source status">
          <ul class="divide-y divide-[var(--color-border)]">
            <For each={sources()}>
              {(src) => (
                <li class="p-4 flex items-center justify-between">
                  <div class="flex items-center gap-4">
                    <div class={`w-2 h-2 rounded-full ${src.status === 'active' ? 'bg-[var(--color-success)] animate-pulse' : 'bg-[var(--color-text-muted)]'}`} aria-hidden="true" />
                    <div>
                      <h3 class="font-medium">{src.name}</h3>
                      <p class="text-xs text-[var(--color-text-muted)]">Last poll: {src.lastPoll}</p>
                    </div>
                  </div>
                  
                  <div class="flex items-center gap-6 text-sm">
                    <div class="text-center">
                      <span class="block font-mono font-bold">{src.findings}</span>
                      <span class="text-[var(--color-text-muted)] text-xs">Findings</span>
                    </div>
                    <div class="text-center">
                      <span class={`block font-mono font-bold ${src.errors > 0 ? 'text-[var(--color-error)]' : ''}`}>
                        {src.errors}
                      </span>
                      <span class="text-[var(--color-text-muted)] text-xs">Errors</span>
                    </div>
                    <Badge severity={src.status === 'active' ? 'success' : 'info'}>
                      {src.status.toUpperCase()}
                    </Badge>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        <Panel as="section" class="p-4 min-h-[200px]" aria-labelledby="logs-heading">
          <h2 id="logs-heading" class="text-lg font-semibold mb-4">Activity Log</h2>
          <EmptyState 
            icon="📝" 
            title="No logs available" 
            description="Start monitoring to see polling activity." 
          />
        </Panel>
      </div>
    </article>
  );
}
