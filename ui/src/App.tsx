import { createSignal, lazy, Suspense, For, type Component } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import { cn } from './lib/styles';
import { Skeleton } from './components/primitives';
import {
  DashboardIcon,
  AnalyzeIcon,
  GlobeIcon,
  MonitorIcon,
  SettingsIcon,
} from './components/icons';

// Lazy load views
const Dashboard = lazy(() => import('./views/Dashboard'));
const Analyze = lazy(() => import('./views/Analyze'));
const Search = lazy(() => import('./views/Search'));
const Monitor = lazy(() => import('./views/Monitor'));
const Settings = lazy(() => import('./views/Settings'));

type View = 'dashboard' | 'analyze' | 'search' | 'monitor' | 'settings';

interface NavItem {
  id: View;
  label: string;
  icon: Component<{ size?: number; class?: string }>;
  description: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon, description: 'Overview and statistics' },
  { id: 'analyze', label: 'Analyze', icon: AnalyzeIcon, description: 'Analyze driver files' },
  { id: 'search', label: 'NVD Search', icon: GlobeIcon, description: 'Search CVE database' },
  { id: 'monitor', label: 'Monitor', icon: MonitorIcon, description: 'Source monitoring' },
  { id: 'settings', label: 'Settings', icon: SettingsIcon, description: 'Configuration' },
];

const VIEW_MAP: Record<View, typeof Dashboard> = {
  dashboard: Dashboard,
  analyze: Analyze,
  search: Search,
  monitor: Monitor,
  settings: Settings,
};

function Sidebar(props: { current: View; onNavigate: (view: View) => void }) {
  return (
    <aside
      class="w-60 bg-[var(--color-surface)] border-r border-[var(--color-border)] flex flex-col"
      aria-label="Main navigation"
    >
      <header class="px-5 py-4 border-b border-[var(--color-border)]">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-[var(--color-accent)] flex items-center justify-center">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              class="w-5 h-5 text-[var(--color-background)]"
            >
              <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
              <path d="M12 8v4" />
              <path d="M12 16h.01" />
            </svg>
          </div>
          <div>
            <h1 class="text-base font-semibold text-[var(--color-text)]">KernelWatch</h1>
            <p class="text-xs text-[var(--color-text-muted)]">Driver Security</p>
          </div>
        </div>
      </header>

      <nav class="flex-1 p-3" aria-label="Primary">
        <ul class="space-y-1" role="list">
          <For each={NAV_ITEMS}>
            {(item) => {
              const isActive = () => props.current === item.id;
              return (
                <li>
                  <button
                    onClick={() => props.onNavigate(item.id)}
                    class={cn(
                      'w-full px-3 py-2.5 rounded-lg text-left flex items-center gap-3 transition-all duration-150',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]',
                      isActive()
                        ? 'bg-[var(--color-accent)] text-[var(--color-background)] font-medium shadow-md'
                        : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]'
                    )}
                    aria-current={isActive() ? 'page' : undefined}
                    title={item.description}
                  >
                    <item.icon
                      size={18}
                      class={isActive() ? 'opacity-100' : 'opacity-70'}
                    />
                    <span class="text-sm">{item.label}</span>
                  </button>
                </li>
              );
            }}
          </For>
        </ul>
      </nav>

      <footer class="px-5 py-4 border-t border-[var(--color-border)]">
        <div class="flex items-center justify-between text-xs text-[var(--color-text-dim)]">
          <span>v0.1.0</span>
          <span class="flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-[var(--color-success)] animate-pulse" />
            Ready
          </span>
        </div>
      </footer>
    </aside>
  );
}

function LoadingFallback() {
  return (
    <section
      class="p-6 space-y-6 animate-fade-in"
      aria-label="Loading content"
      aria-busy="true"
    >
      <div class="space-y-2">
        <Skeleton height="1.75rem" width="10rem" />
        <Skeleton height="1rem" width="16rem" />
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-8">
        <Skeleton height="6rem" />
        <Skeleton height="6rem" />
        <Skeleton height="6rem" />
        <Skeleton height="6rem" />
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Skeleton height="12rem" />
        <Skeleton height="12rem" />
      </div>
    </section>
  );
}

export default function App() {
  const [currentView, setCurrentView] = createSignal<View>('dashboard');

  return (
    <div class="flex h-screen bg-[var(--color-background)] text-[var(--color-text)]">
      <Sidebar current={currentView()} onNavigate={setCurrentView} />

      <main
        class="flex-1 overflow-auto"
        id="main-content"
        role="main"
        aria-label={`${NAV_ITEMS.find((n) => n.id === currentView())?.label} view`}
      >
        <Suspense fallback={<LoadingFallback />}>
          <Dynamic component={VIEW_MAP[currentView()]} />
        </Suspense>
      </main>
    </div>
  );
}
