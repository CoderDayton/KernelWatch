/**
 * Settings View
 */
import { Panel } from '../components/primitives';

export default function Settings() {
  return (
    <article class="p-6 max-w-5xl mx-auto">
      <header class="mb-8">
        <h1 class="text-2xl font-bold">Settings</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Configure API keys and application preferences.
        </p>
      </header>

      <Panel class="p-6">
        <p class="text-[var(--color-text-muted)]">
          Settings are currently configured via the <code>.env</code> file in the project root.
          UI configuration will be available in a future update.
        </p>
        
        <div class="mt-6 space-y-4">
          <h3 class="font-medium text-[var(--color-text)]">Current Configuration Sources</h3>
          <ul class="list-disc list-inside text-sm text-[var(--color-text-dim)] space-y-1">
            <li>NVD API Key: Env var <code>DRIVER_SEARCH_NVD_API_KEY</code></li>
            <li>VirusTotal API Key: Env var <code>DRIVER_SEARCH_VIRUSTOTAL_API_KEY</code></li>
            <li>GitHub Token: Env var <code>DRIVER_SEARCH_GITHUB_TOKEN</code></li>
          </ul>
        </div>
      </Panel>
    </article>
  );
}
