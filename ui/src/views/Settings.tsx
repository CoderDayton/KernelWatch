/**
 * Settings View - Configuration and API keys
 * Semantic: form sections with proper labels
 */
import { createSignal, For, type Component } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import { Panel, Badge } from '../components/primitives';
import {
  GlobeIcon,
  ShieldIcon,
  DatabaseIcon,
  CheckIcon,
  XIcon,
} from '../components/icons';

type IconComponent = Component<{ size?: number; class?: string }>;

interface ApiKeyConfig {
  id: string;
  name: string;
  envVar: string;
  icon: IconComponent;
  description: string;
  required: boolean;
  docsUrl?: string;
}

const API_KEYS: ApiKeyConfig[] = [
  {
    id: 'nvd',
    name: 'NVD API Key',
    envVar: 'KERNEL_WATCH_NVD_API_KEY',
    icon: GlobeIcon,
    description: 'Required for CVE searches. Get one free from NVD.',
    required: false,
    docsUrl: 'https://nvd.nist.gov/developers/request-an-api-key',
  },
  {
    id: 'virustotal',
    name: 'VirusTotal API Key',
    envVar: 'KERNEL_WATCH_VIRUSTOTAL_API_KEY',
    icon: ShieldIcon,
    description: 'Enables file hash reputation checks.',
    required: false,
    docsUrl: 'https://www.virustotal.com/gui/my-apikey',
  },
  {
    id: 'github',
    name: 'GitHub Token',
    envVar: 'KERNEL_WATCH_GITHUB_TOKEN',
    icon: DatabaseIcon,
    description: 'Increases rate limits for LOLDrivers sync.',
    required: false,
    docsUrl: 'https://github.com/settings/tokens',
  },
];

interface SettingGroup {
  title: string;
  description: string;
  settings: {
    id: string;
    label: string;
    envVar: string;
    type: 'number' | 'text' | 'boolean';
    default: string;
  }[];
}

const SETTING_GROUPS: SettingGroup[] = [
  {
    title: 'Analysis Settings',
    description: 'Configure driver analysis behavior',
    settings: [
      {
        id: 'max_file_size',
        label: 'Max File Size (MB)',
        envVar: 'KERNEL_WATCH_ANALYSIS_MAX_FILE_SIZE_MB',
        type: 'number',
        default: '50',
      },
      {
        id: 'import_depth',
        label: 'Import Analysis Depth',
        envVar: 'KERNEL_WATCH_ANALYSIS_IMPORT_DEPTH',
        type: 'number',
        default: '2',
      },
    ],
  },
  {
    title: 'Monitoring Settings',
    description: 'Configure source polling intervals',
    settings: [
      {
        id: 'poll_interval',
        label: 'Poll Interval (seconds)',
        envVar: 'KERNEL_WATCH_MONITOR_POLL_INTERVAL_SECONDS',
        type: 'number',
        default: '300',
      },
    ],
  },
];

export default function Settings() {
  // In a real app, these would be fetched from the backend
  const [keyStatus] = createSignal<Record<string, boolean>>({
    nvd: false,
    virustotal: false,
    github: false,
  });

  return (
    <article class="p-6 max-w-4xl mx-auto animate-fade-in">
      <header class="mb-8">
        <h1 class="text-2xl font-semibold tracking-tight">Settings</h1>
        <p class="text-[var(--color-text-muted)] mt-1">
          Configure API keys and application preferences.
        </p>
      </header>

      <div class="space-y-8">
        {/* API Keys Section */}
        <Panel as="section" title="API Keys" description="External service credentials" variant="raised">
          <ul class="divide-y divide-[var(--color-border)]" role="list">
            <For each={API_KEYS}>
              {(key) => {
                const isConfigured = () => keyStatus()[key.id];

                return (
                  <li class="py-4 first:pt-0 last:pb-0">
                    <div class="flex items-start gap-4">
                      <div class="p-2 rounded-lg bg-[var(--color-surface-raised)] shrink-0">
                        <Dynamic component={key.icon} size={20} class="text-[var(--color-accent)]" />
                      </div>
                      <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                          <h3 class="font-medium text-[var(--color-text)]">{key.name}</h3>
                          <Badge
                            severity={isConfigured() ? 'success' : 'info'}
                            icon={isConfigured() ? CheckIcon : XIcon}
                          >
                            {isConfigured() ? 'Configured' : 'Not Set'}
                          </Badge>
                        </div>
                        <p class="text-sm text-[var(--color-text-muted)] mt-1">{key.description}</p>
                        <code class="text-xs text-[var(--color-accent)] font-mono mt-2 block">
                          {key.envVar}
                        </code>
                      </div>
                      {key.docsUrl && (
                        <a
                          href={key.docsUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          class="text-sm text-[var(--color-accent)] hover:underline shrink-0"
                        >
                          Get Key →
                        </a>
                      )}
                    </div>
                  </li>
                );
              }}
            </For>
          </ul>
        </Panel>

        {/* Configuration Info */}
        <Panel
          as="section"
          title="Configuration"
          description="Settings are configured via environment variables"
          variant="raised"
        >
          <div class="bg-[var(--color-surface-raised)] rounded-lg p-4 border border-[var(--color-border)]">
            <p class="text-sm text-[var(--color-text-secondary)]">
              All settings are configured through environment variables or a{' '}
              <code class="text-[var(--color-accent)]">.env</code> file in the application data
              directory.
            </p>
            <p class="text-sm text-[var(--color-text-muted)] mt-2">
              Data directory:{' '}
              <code class="text-[var(--color-accent)]">~/.local/share/kernel-watch/</code>
            </p>
          </div>

          <div class="mt-6 space-y-6">
            <For each={SETTING_GROUPS}>
              {(group) => (
                <div>
                  <h3 class="text-sm font-semibold text-[var(--color-text)] mb-1">{group.title}</h3>
                  <p class="text-xs text-[var(--color-text-muted)] mb-3">{group.description}</p>
                  <ul class="space-y-2" role="list">
                    <For each={group.settings}>
                      {(setting) => (
                        <li class="flex items-center justify-between py-2 border-b border-[var(--color-border)] last:border-0">
                          <div>
                            <span class="text-sm text-[var(--color-text)]">{setting.label}</span>
                            <code class="text-xs text-[var(--color-text-dim)] font-mono block mt-0.5">
                              {setting.envVar}
                            </code>
                          </div>
                          <span class="text-sm text-[var(--color-text-muted)] font-mono">
                            Default: {setting.default}
                          </span>
                        </li>
                      )}
                    </For>
                  </ul>
                </div>
              )}
            </For>
          </div>
        </Panel>

        {/* About Section */}
        <Panel as="section" title="About" variant="raised">
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-xl bg-[var(--color-accent)] flex items-center justify-center">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class="w-6 h-6 text-[var(--color-background)]"
              >
                <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                <path d="M12 8v4" />
                <path d="M12 16h.01" />
              </svg>
            </div>
            <div>
              <h3 class="font-semibold text-[var(--color-text)]">KernelWatch</h3>
              <p class="text-sm text-[var(--color-text-muted)]">
                Windows Driver Security Research Tool
              </p>
              <p class="text-xs text-[var(--color-text-dim)] mt-1">Version 0.1.0</p>
            </div>
          </div>
        </Panel>
      </div>
    </article>
  );
}
