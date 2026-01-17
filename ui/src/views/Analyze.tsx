/**
 * Analyze View - Driver file analysis
 * Semantic: form > input group > results region
 */
import { createSignal, Show, For, Switch, Match } from 'solid-js';
import { analyzeDriver, type AnalysisResult } from '../lib/sidecar';
import { Button, Input, Panel, Badge, DataTable } from '../components/primitives';
import { cn } from '../lib/styles';

function AnalysisResults(props: { result: AnalysisResult }) {
  const [activeTab, setActiveTab] = createSignal<'overview' | 'vulns' | 'imports'>('overview');
  const r = () => props.result;

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'vulns', label: `Vulnerabilities (${r().vulnerabilities.length})` },
    { id: 'imports', label: `Dangerous Imports (${r().dangerous_imports.length})` },
  ] as const;

  return (
    <Panel class="mt-6 overflow-hidden bg-[var(--color-surface)]" aria-label="Analysis results">
      {/* Header */}
      <header class="p-4 border-b border-[var(--color-border)] flex items-center justify-between">
        <div>
          <h2 class="text-lg font-semibold">{r().driver.name}</h2>
          <code class="text-xs text-[var(--color-text-muted)] font-mono">{r().driver.hashes.sha256}</code>
        </div>
        <Badge severity={r().risk_level} class="text-sm font-medium px-3 py-1">
          {r().risk_level.toUpperCase()} ({r().risk_score})
        </Badge>
      </header>

      {/* Tabs */}
      <nav class="flex border-b border-[var(--color-border)] px-4" aria-label="Result sections">
        <For each={tabs}>
          {(tab) => (
            <button
              onClick={() => setActiveTab(tab.id)}
              class={cn(
                'px-4 py-3 text-sm font-medium transition-colors border-b-2',
                activeTab() === tab.id
                  ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                  : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text)]'
              )}
              aria-current={activeTab() === tab.id ? 'page' : undefined}
            >
              {tab.label}
            </button>
          )}
        </For>
      </nav>

      {/* Content */}
      <div class="p-4 min-h-[300px]" role="tabpanel">
        <Switch>
          <Match when={activeTab() === 'overview'}>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-6 text-sm">
              {[
                { label: 'Vendor', value: r().driver.vendor },
                { label: 'Version', value: r().driver.version },
                { label: 'Signer', value: r().driver.signer, mono: true },
                { label: 'Compiled', value: r().driver.compile_time },
                { label: 'LOLDrivers', value: r().in_loldrivers ? 'Known Vulnerable' : 'Not Listed', severity: r().in_loldrivers ? 'warning' : 'success' },
                { label: 'VirusTotal', value: r().vt_detections !== undefined ? `${r().vt_detections}/${r().vt_total}` : 'Not Checked' },
              ].map((item) => (
                <div class="flex flex-col gap-1">
                  <dt class="text-[var(--color-text-muted)]">{item.label}</dt>
                  <dd class={cn('font-medium', item.mono && 'font-mono text-xs')}>
                    <Show when={item.severity} fallback={item.value || '-'}>
                      <span class={cn(
                        item.severity === 'warning' ? 'text-[var(--color-warning)]' : 
                        item.severity === 'success' ? 'text-[var(--color-success)]' : ''
                      )}>
                        {item.value}
                      </span>
                    </Show>
                  </dd>
                </div>
              ))}
            </dl>
          </Match>

          <Match when={activeTab() === 'vulns'}>
            <DataTable
              data={r().vulnerabilities}
              aria-label="Vulnerabilities list"
              rowKey={(v) => v.description}
              emptyMessage="No vulnerabilities detected"
              columns={[
                { key: 'vuln_type', header: 'Type', render: (v) => <code class="text-xs text-[var(--color-accent)]">{v.vuln_type}</code> },
                { key: 'description', header: 'Description', class: 'w-1/2' },
                { key: 'confidence', header: 'Confidence', render: (v) => `${(v.confidence * 100).toFixed(0)}%` },
                { key: 'cve_id', header: 'CVE', render: (v) => v.cve_id || '-' },
              ]}
            />
          </Match>

          <Match when={activeTab() === 'imports'}>
            <Show when={r().dangerous_imports.length > 0} fallback={<p class="text-[var(--color-text-muted)] text-sm">No dangerous imports detected.</p>}>
              <ul class="grid grid-cols-2 md:grid-cols-3 gap-2" aria-label="Dangerous imports">
                <For each={r().dangerous_imports}>
                  {(imp) => (
                    <li>
                      <code class="px-2 py-1 rounded bg-[var(--color-error)]/10 text-[var(--color-error)] text-sm border border-[var(--color-error)]/20 block text-center">
                        {imp}
                      </code>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </Match>
        </Switch>
      </div>
    </Panel>
  );
}

export default function Analyze() {
  const [path, setPath] = createSignal('');
  const [result, setResult] = createSignal<AnalysisResult | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    if (!path()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeDriver(path());
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <article class="p-6 max-w-5xl mx-auto">
      <header class="mb-8">
        <h1 class="text-2xl font-bold">Analyze Driver</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Scan a driver binary for vulnerabilities, IOCTL handlers, and dangerous imports.
        </p>
      </header>

      <form onSubmit={handleSubmit} class="flex gap-4 items-start" aria-label="Analysis form">
        <div class="flex-1">
          <Input
            value={path()}
            onInput={(e) => setPath(e.currentTarget.value)}
            placeholder="/path/to/driver.sys"
            aria-label="Driver file path"
            disabled={loading()}
            error={error() || undefined}
          />
        </div>
        <Button type="submit" loading={loading()} disabled={!path()}>
          Analyze
        </Button>
      </form>

      <Show when={result()}>
        {(res) => <AnalysisResults result={res()} />}
      </Show>
    </article>
  );
}
