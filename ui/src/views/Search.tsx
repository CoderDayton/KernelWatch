/**
 * Search View - NVD CVE Search
 * Semantic: form > results region
 */
import { createSignal, Show } from 'solid-js';
import { searchNVD, type CVEEntry } from '../lib/sidecar';
import { Button, Input, DataTable, Panel, Badge } from '../components/primitives';
import { SearchIcon, GlobeIcon, ExternalLinkIcon, ShieldAlertIcon } from '../components/icons';

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

  const getSeverityFromCvss = (score?: number): 'critical' | 'high' | 'medium' | 'low' | 'info' => {
    if (!score) return 'info';
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  };

  return (
    <article class="p-6 max-w-6xl mx-auto animate-fade-in">
      <header class="mb-8">
        <h1 class="text-2xl font-semibold tracking-tight">CVE Search</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Search the National Vulnerability Database for driver-related CVEs.
        </p>
      </header>

      <Panel as="section" variant="raised" class="p-6">
        <form onSubmit={handleSearch} class="flex gap-4 items-start" aria-label="Search form">
          <div class="flex-1">
            <Input
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              placeholder="e.g. 'motherboard overclock' or 'ASUS driver'"
              label="Search Query"
              hint="Enter keywords to find related CVE entries"
              icon={SearchIcon}
              disabled={loading()}
              error={error() || undefined}
            />
          </div>
          <div class="pt-6">
            <Button
              type="submit"
              loading={loading()}
              disabled={!query()}
              icon={GlobeIcon}
            >
              {loading() ? 'Searching...' : 'Search NVD'}
            </Button>
          </div>
        </form>
      </Panel>

      <Show when={searched() || results().length > 0}>
        <Panel class="mt-6" variant="raised" aria-label="Search results">
          <DataTable
            data={results()}
            loading={loading()}
            rowKey={(c) => c.cve_id}
            emptyMessage={searched() ? 'No CVEs found matching your query.' : 'Enter a query to search.'}
            emptyIcon={ShieldAlertIcon}
            aria-label="CVE search results"
            columns={[
              {
                key: 'cve_id',
                header: 'CVE ID',
                class: 'w-36 font-mono text-sm',
                render: (c) => (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-1.5 text-[var(--color-accent)] hover:underline"
                  >
                    {c.cve_id}
                    <ExternalLinkIcon size={12} class="opacity-50" />
                  </a>
                ),
              },
              {
                key: 'cvss_score',
                header: 'CVSS',
                class: 'w-24',
                render: (c) => (
                  <Badge severity={getSeverityFromCvss(c.cvss_score)} class="font-mono">
                    {c.cvss_score?.toFixed(1) || 'N/A'}
                  </Badge>
                ),
              },
              {
                key: 'published',
                header: 'Published',
                class: 'w-28 text-[var(--color-text-secondary)]',
                render: (c) => c.published.split('T')[0],
              },
              {
                key: 'description',
                header: 'Description',
                render: (c) => (
                  <p
                    class="line-clamp-2 text-sm text-[var(--color-text-muted)]"
                    title={c.description}
                  >
                    {c.description}
                  </p>
                ),
              },
            ]}
          />
        </Panel>
      </Show>
    </article>
  );
}
