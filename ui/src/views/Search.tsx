/**
 * Search View - NVD CVE Search
 */
import { createSignal, Show } from 'solid-js';
import { searchNVD, type CVEEntry } from '../lib/sidecar';
import { Button, Input, DataTable, Panel } from '../components/primitives';

export default function Search() {
  const [query, setQuery] = createSignal('');
  const [results, setResults] = createSignal<CVEEntry[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [searched, setSearched] = createSignal(false);

  const handleSearch = async (e: Event) => {
    e.preventDefault();
    if (!query()) return;

    setLoading(true);
    setError(null);
    setSearched(true);
    
    try {
      const res = await searchNVD(query());
      setResults(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed');
    } finally {
      setLoading(false);
    }
  };

  const getCvssColor = (score?: number) => {
    if (!score) return 'text-[var(--color-text-muted)]';
    if (score >= 9.0) return 'text-[var(--color-critical)] font-bold';
    if (score >= 7.0) return 'text-[var(--color-high)] font-bold';
    if (score >= 4.0) return 'text-[var(--color-medium)]';
    return 'text-[var(--color-low)]';
  };

  return (
    <article class="p-6 max-w-5xl mx-auto">
      <header class="mb-8">
        <h1 class="text-2xl font-bold">CVE Search</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Search the National Vulnerability Database (NVD) for driver-related CVEs.
        </p>
      </header>

      <form onSubmit={handleSearch} class="flex gap-4 mb-8" aria-label="Search form">
        <div class="flex-1">
          <Input
            value={query()}
            onInput={(e) => setQuery(e.currentTarget.value)}
            placeholder="e.g. 'motherboard overclock' or 'ASUS driver'"
            aria-label="Search query"
            disabled={loading()}
            error={error() || undefined}
          />
        </div>
        <Button type="submit" loading={loading()} disabled={!query()}>
          Search NVD
        </Button>
      </form>

      <Show when={searched || results().length > 0}>
        <Panel>
          <DataTable
            data={results()}
            loading={loading()}
            rowKey={(c) => c.cve_id}
            emptyMessage={searched() ? "No CVEs found matching your query." : "Enter a query to search."}
            aria-label="Search results"
            columns={[
              { 
                key: 'cve_id', 
                header: 'CVE ID', 
                class: 'w-32 font-mono',
                render: (c) => (
                  <a 
                    href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    class="text-[var(--color-accent)] hover:underline"
                  >
                    {c.cve_id}
                  </a>
                )
              },
              { 
                key: 'cvss_score', 
                header: 'CVSS', 
                class: 'w-20 text-center',
                render: (c) => (
                  <span class={getCvssColor(c.cvss_score)}>
                    {c.cvss_score?.toFixed(1) || '-'}
                  </span>
                )
              },
              { 
                key: 'published', 
                header: 'Published', 
                class: 'w-32',
                render: (c) => c.published.split('T')[0] 
              },
              { 
                key: 'description', 
                header: 'Description',
                render: (c) => (
                  <p class="line-clamp-2 text-sm text-[var(--color-text-dim)]" title={c.description}>
                    {c.description}
                  </p>
                )
              },
            ]}
          />
        </Panel>
      </Show>
    </article>
  );
}
