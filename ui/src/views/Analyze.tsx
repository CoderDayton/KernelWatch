import { createSignal, Show, For } from 'solid-js';
import { Tabs } from '@kobalte/core/tabs';
import { analyzeDriver, type AnalysisResult } from '../lib/sidecar';

function RiskBadge(props: { level: string; score: number }) {
  const colorClass = () => {
    switch (props.level) {
      case 'critical': return 'bg-critical/20 text-critical border-critical/40';
      case 'high': return 'bg-high/20 text-high border-high/40';
      case 'medium': return 'bg-medium/20 text-medium border-medium/40';
      case 'low': return 'bg-low/20 text-low border-low/40';
      default: return 'bg-info/20 text-info border-info/40';
    }
  };

  return (
    <span class={`px-2 py-1 rounded border text-sm font-mono ${colorClass()}`}>
      {props.level.toUpperCase()} ({props.score})
    </span>
  );
}

export default function Analyze() {
  const [filePath, setFilePath] = createSignal('');
  const [result, setResult] = createSignal<AnalysisResult | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const handleAnalyze = async () => {
    if (!filePath()) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const res = await analyzeDriver(filePath());
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Analyze Driver</h1>

      {/* File Input */}
      <div class="flex gap-4 mb-6">
        <input
          type="text"
          placeholder="Path to driver file (.sys)"
          value={filePath()}
          onInput={(e) => setFilePath(e.currentTarget.value)}
          class="flex-1 px-4 py-2 rounded bg-surface border border-border text-text 
                 placeholder:text-text-dim focus:outline-none focus:border-accent"
        />
        <button
          onClick={handleAnalyze}
          disabled={loading() || !filePath()}
          class="px-6 py-2 rounded bg-accent text-background font-medium
                 hover:bg-accent-bright disabled:opacity-50 disabled:cursor-not-allowed
                 transition-colors"
        >
          {loading() ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      {/* Error */}
      <Show when={error()}>
        <div class="mb-6 p-4 rounded border border-error/40 bg-error/10 text-error">
          {error()}
        </div>
      </Show>

      {/* Results */}
      <Show when={result()}>
        {(r) => (
          <div class="border border-border rounded-lg bg-surface overflow-hidden">
            {/* Header */}
            <div class="p-4 border-b border-border flex items-center justify-between">
              <div>
                <h2 class="text-lg font-semibold">{r().driver.name}</h2>
                <code class="text-xs text-text-muted">{r().driver.hashes.sha256}</code>
              </div>
              <RiskBadge level={r().risk_level} score={r().risk_score} />
            </div>

            {/* Tabs */}
            <Tabs class="w-full">
              <Tabs.List class="flex border-b border-border">
                <Tabs.Trigger
                  value="overview"
                  class="px-4 py-2 text-text-muted hover:text-text data-[selected]:text-accent 
                         data-[selected]:border-b-2 data-[selected]:border-accent transition-colors"
                >
                  Overview
                </Tabs.Trigger>
                <Tabs.Trigger
                  value="vulnerabilities"
                  class="px-4 py-2 text-text-muted hover:text-text data-[selected]:text-accent 
                         data-[selected]:border-b-2 data-[selected]:border-accent transition-colors"
                >
                  Vulnerabilities ({r().vulnerabilities.length})
                </Tabs.Trigger>
                <Tabs.Trigger
                  value="imports"
                  class="px-4 py-2 text-text-muted hover:text-text data-[selected]:text-accent 
                         data-[selected]:border-b-2 data-[selected]:border-accent transition-colors"
                >
                  Dangerous Imports ({r().dangerous_imports.length})
                </Tabs.Trigger>
              </Tabs.List>

              <Tabs.Content value="overview" class="p-4">
                <div class="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span class="text-text-muted">Vendor:</span>
                    <span class="ml-2">{r().driver.vendor || 'Unknown'}</span>
                  </div>
                  <div>
                    <span class="text-text-muted">Version:</span>
                    <span class="ml-2">{r().driver.version || 'Unknown'}</span>
                  </div>
                  <div>
                    <span class="text-text-muted">Signer:</span>
                    <span class="ml-2 font-mono text-xs">{r().driver.signer || 'Unsigned'}</span>
                  </div>
                  <div>
                    <span class="text-text-muted">Compiled:</span>
                    <span class="ml-2">{r().driver.compile_time || 'Unknown'}</span>
                  </div>
                  <div>
                    <span class="text-text-muted">In LOLDrivers:</span>
                    <span class={`ml-2 ${r().in_loldrivers ? 'text-warning' : 'text-success'}`}>
                      {r().in_loldrivers ? 'Yes (known vulnerable)' : 'No (potential new finding)'}
                    </span>
                  </div>
                  <div>
                    <span class="text-text-muted">VirusTotal:</span>
                    <span class="ml-2">
                      {r().vt_detections !== undefined 
                        ? `${r().vt_detections}/${r().vt_total}` 
                        : 'Not checked'}
                    </span>
                  </div>
                </div>

                <Show when={r().notes.length > 0}>
                  <div class="mt-4 pt-4 border-t border-border">
                    <h3 class="font-medium mb-2">Notes</h3>
                    <ul class="list-disc list-inside text-sm text-text-muted">
                      <For each={r().notes}>
                        {(note) => <li>{note}</li>}
                      </For>
                    </ul>
                  </div>
                </Show>
              </Tabs.Content>

              <Tabs.Content value="vulnerabilities" class="p-4">
                <Show 
                  when={r().vulnerabilities.length > 0}
                  fallback={<div class="text-text-muted">No vulnerabilities detected</div>}
                >
                  <div class="space-y-3">
                    <For each={r().vulnerabilities}>
                      {(vuln) => (
                        <div class="p-3 rounded border border-border bg-surface-raised">
                          <div class="flex items-center justify-between mb-1">
                            <span class="font-mono text-sm text-accent">{vuln.vuln_type}</span>
                            <span class="text-xs text-text-muted">
                              {(vuln.confidence * 100).toFixed(0)}% confidence
                            </span>
                          </div>
                          <p class="text-sm text-text-muted">{vuln.description}</p>
                          <Show when={vuln.cve_id}>
                            <a 
                              href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                              target="_blank"
                              class="text-xs text-accent hover:underline mt-1 inline-block"
                            >
                              {vuln.cve_id}
                            </a>
                          </Show>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </Tabs.Content>

              <Tabs.Content value="imports" class="p-4">
                <Show 
                  when={r().dangerous_imports.length > 0}
                  fallback={<div class="text-text-muted">No dangerous imports detected</div>}
                >
                  <div class="grid grid-cols-2 md:grid-cols-3 gap-2">
                    <For each={r().dangerous_imports}>
                      {(imp) => (
                        <code class="px-2 py-1 rounded bg-error/10 text-error text-sm border border-error/30">
                          {imp}
                        </code>
                      )}
                    </For>
                  </div>
                </Show>
              </Tabs.Content>
            </Tabs>
          </div>
        )}
      </Show>
    </div>
  );
}
