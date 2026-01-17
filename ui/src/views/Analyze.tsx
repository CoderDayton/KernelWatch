/**
 * Analyze View - Driver file analysis
 * Semantic: form > input group > results region
 */
import { createSignal, Show, For } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import { analyzeDriver, type AnalysisResult } from '../lib/sidecar';
import { Button, Input, Panel, Badge, DataTable, Tabs, TabPanel, EmptyState } from '../components/primitives';
import { cn } from '../lib/styles';
import {
  UploadIcon,
  FileIcon,
  ShieldCheckIcon,
  ShieldAlertIcon,
  BugIcon,
  AlertTriangleIcon,
  CheckIcon,
  ExternalLinkIcon,
} from '../components/icons';

function AnalysisResults(props: { result: AnalysisResult }) {
  const [activeTab, setActiveTab] = createSignal('overview');
  const r = () => props.result;

  const tabs = [
    { id: 'overview', label: 'Overview', icon: FileIcon },
    { id: 'vulns', label: `Vulnerabilities (${r().vulnerabilities.length})`, icon: BugIcon },
    { id: 'imports', label: `Dangerous Imports (${r().dangerous_imports.length})`, icon: AlertTriangleIcon },
  ];

  const riskIcon = () => {
    const level = r().risk_level;
    return level === 'critical' || level === 'high' ? ShieldAlertIcon : ShieldCheckIcon;
  };

  return (
    <Panel class="mt-6 overflow-hidden" variant="raised" aria-label="Analysis results">
      {/* Header */}
      <header class="p-5 border-b border-[var(--color-border)] flex items-start justify-between gap-4 bg-[var(--color-surface)]">
        <div class="flex items-start gap-4">
          <div class="p-3 rounded-lg bg-[var(--color-surface-raised)]">
            <FileIcon size={24} class="text-[var(--color-accent)]" />
          </div>
          <div>
            <h2 class="text-lg font-semibold text-[var(--color-text)]">{r().driver.name}</h2>
            <code class="text-xs text-[var(--color-text-muted)] font-mono block mt-1 break-all">
              {r().driver.hashes.sha256}
            </code>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <div class="text-right">
            <p class="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">Risk Score</p>
            <p class="text-2xl font-bold font-mono">{r().risk_score}</p>
          </div>
          <Badge severity={r().risk_level} icon={riskIcon()} class="text-sm font-medium px-3 py-1.5">
            {r().risk_level.toUpperCase()}
          </Badge>
        </div>
      </header>

      {/* Tabs */}
      <Tabs
        tabs={tabs}
        active={activeTab()}
        onChange={setActiveTab}
        class="px-5 bg-[var(--color-surface)]"
      />

      {/* Content */}
      <div class="p-5 min-h-[320px]">
        <TabPanel id="overview" active={activeTab()}>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <DetailItem label="Vendor" value={r().driver.vendor} />
            <DetailItem label="Version" value={r().driver.version} />
            <DetailItem label="Signer" value={r().driver.signer} mono />
            <DetailItem label="Compiled" value={r().driver.compile_time} />
            <DetailItem
              label="LOLDrivers Status"
              value={r().in_loldrivers ? 'Known Vulnerable' : 'Not Listed'}
              icon={r().in_loldrivers ? AlertTriangleIcon : CheckIcon}
              status={r().in_loldrivers ? 'warning' : 'success'}
            />
            <DetailItem
              label="VirusTotal"
              value={r().vt_detections !== undefined ? `${r().vt_detections}/${r().vt_total} detections` : 'Not checked'}
              status={(r().vt_detections ?? 0) > 0 ? 'error' : 'neutral'}
            />
          </div>
        </TabPanel>

        <TabPanel id="vulns" active={activeTab()}>
          <Show
            when={r().vulnerabilities.length > 0}
            fallback={
              <EmptyState
                icon={ShieldCheckIcon}
                title="No vulnerabilities detected"
                description="This driver passed all vulnerability checks."
              />
            }
          >
            <DataTable
              data={r().vulnerabilities}
              aria-label="Vulnerabilities list"
              rowKey={(v) => v.description}
              emptyMessage="No vulnerabilities detected"
              columns={[
                {
                  key: 'vuln_type',
                  header: 'Type',
                  render: (v) => (
                    <Badge severity="critical" class="font-mono text-xs">
                      {v.vuln_type}
                    </Badge>
                  ),
                },
                { key: 'description', header: 'Description', class: 'max-w-md' },
                {
                  key: 'confidence',
                  header: 'Confidence',
                  render: (v) => (
                    <span class="font-mono text-sm">
                      {(v.confidence * 100).toFixed(0)}%
                    </span>
                  ),
                },
                {
                  key: 'cve_id',
                  header: 'CVE',
                  render: (v) =>
                    v.cve_id ? (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        class="inline-flex items-center gap-1 text-[var(--color-accent)] hover:underline"
                      >
                        {v.cve_id}
                        <ExternalLinkIcon size={12} />
                      </a>
                    ) : (
                      <span class="text-[var(--color-text-dim)]">—</span>
                    ),
                },
              ]}
            />
          </Show>
        </TabPanel>

        <TabPanel id="imports" active={activeTab()}>
          <Show
            when={r().dangerous_imports.length > 0}
            fallback={
              <EmptyState
                icon={ShieldCheckIcon}
                title="No dangerous imports found"
                description="No commonly abused kernel APIs were detected in this driver."
              />
            }
          >
            <p class="text-sm text-[var(--color-text-muted)] mb-4">
              The following kernel APIs are commonly abused for privilege escalation or system manipulation:
            </p>
            <ul class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2" role="list">
              <For each={r().dangerous_imports}>
                {(imp) => (
                  <li>
                    <code class="block px-3 py-2 rounded-lg bg-[var(--color-error-bg)] text-[var(--color-error)] text-sm font-mono border border-[var(--color-error)]/20 text-center truncate">
                      {imp}
                    </code>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </TabPanel>
      </div>
    </Panel>
  );
}

function DetailItem(props: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
  icon?: typeof CheckIcon;
  status?: 'success' | 'warning' | 'error' | 'neutral';
}) {
  const statusColors = {
    success: 'text-[var(--color-success)]',
    warning: 'text-[var(--color-warning)]',
    error: 'text-[var(--color-error)]',
    neutral: 'text-[var(--color-text)]',
  };

  return (
    <div class="flex flex-col gap-1">
      <dt class="text-xs uppercase tracking-wider text-[var(--color-text-muted)]">
        {props.label}
      </dt>
      <dd
        class={cn(
          'font-medium flex items-center gap-2',
          props.mono && 'font-mono text-sm',
          props.status && statusColors[props.status]
        )}
      >
        <Show when={props.icon}>
          <Dynamic component={props.icon} size={16} />
        </Show>
        <span class="truncate">{props.value || '—'}</span>
      </dd>
    </div>
  );
}

export default function Analyze() {
  const [path, setPath] = createSignal('');
  const [result, setResult] = createSignal<AnalysisResult | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    if (!path().trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await analyzeDriver(path().trim());
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <article class="p-6 max-w-6xl mx-auto animate-fade-in">
      <header class="mb-8">
        <h1 class="text-2xl font-semibold tracking-tight">Analyze Driver</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Scan a driver binary for vulnerabilities, IOCTL handlers, and dangerous imports.
        </p>
      </header>

      <Panel as="section" variant="raised" class="p-6">
        <form onSubmit={handleSubmit} class="space-y-4" aria-label="Analysis form">
          <div class="flex gap-4 items-start">
            <div class="flex-1">
              <Input
                value={path()}
                onInput={(e) => setPath(e.currentTarget.value)}
                placeholder="/path/to/driver.sys"
                label="Driver File Path"
                hint="Enter the full path to a Windows driver (.sys) file"
                icon={FileIcon}
                disabled={loading()}
                error={error() || undefined}
              />
            </div>
            <div class="pt-6">
              <Button
                type="submit"
                loading={loading()}
                disabled={!path().trim()}
                icon={UploadIcon}
              >
                {loading() ? 'Analyzing...' : 'Analyze'}
              </Button>
            </div>
          </div>
        </form>
      </Panel>

      <Show when={result()}>{(res) => <AnalysisResults result={res()} />}</Show>
    </article>
  );
}
