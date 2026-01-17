import { createSignal, lazy, Suspense, For } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import { cn } from './lib/styles';
import { Skeleton } from './components/primitives';

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
  icon: string;
  description: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊', description: 'Overview and statistics' },
  { id: 'analyze', label: 'Analyze', icon: '🔍', description: 'Analyze driver files' },
  { id: 'search', label: 'NVD Search', icon: '🌐', description: 'Search CVE database' },
  { id: 'monitor', label: 'Monitor', icon: '📡', description: 'Source monitoring' },
  { id: 'settings', label: 'Settings', icon: '⚙️', description: 'Configuration' },
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
      class="w-56 bg-[var(--color-surface)] border-r border-[var(--color-border)] flex flex-col"
      aria-label="Main navigation"
    >
      <header class="p-4 border-b border-[var(--color-border)]">
        <h1 class="text-lg font-bold text-[var(--color-accent)]">KernelWatch</h1>
        <p class="text-xs text-[var(--color-text-muted)]">Vulnerable Driver Research</p>
      </header>

      <nav class="flex-1 p-2" aria-label="Primary">
        <ul class="space-y-1" role="list">
          <For each={NAV_ITEMS}>
            {(item) => (
              <li>
                <button
                  onClick={() => props.onNavigate(item.id)}
                  class={cn(
                    'w-full px-3 py-2 rounded text-left flex items-center gap-2 transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset'
                  )}
                  data-active={props.current === item.id || undefined}
                  aria-current={props.current === item.id ? 'page' : undefined}
                  title={item.description}
                  style={{
                    background: props.current === item.id ? 'var(--color-accent)' : 'transparent',
                    color: props.current === item.id ? 'var(--color-background)' : 'var(--color-text-muted)',
                    opacity: props.current === item.id ? 1 : 0.8,
                  }}
                >
                  <span aria-hidden="true">{item.icon}</span>
                  <span>{item.label}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
      </nav>

      <footer class="p-4 border-t border-[var(--color-border)] text-xs text-[var(--color-text-dim)]">
        <p>v0.1.0</p>
      </footer>
    </aside>
  );
}

function LoadingFallback() {
  return (
    <section 
      class="p-6 space-y-4" 
      aria-label="Loading content"
      aria-busy="true"
    >
      <Skeleton height="2rem" width="12rem" />
      <Skeleton height="1rem" width="20rem" />
      <section class="grid grid-cols-3 gap-4 mt-6">
        <Skeleton height="5rem" />
        <Skeleton height="5rem" />
        <Skeleton height="5rem" />
      </section>
    </section>
  );
}

export default function App() {
  const [currentView, setCurrentView] = createSignal<View>('dashboard');

  return (
    <div class="flex h-screen bg-[var(--color-background)]">
      <Sidebar current={currentView()} onNavigate={setCurrentView} />
      
      <main 
        class="flex-1 overflow-auto"
        id="main-content"
        role="main"
        aria-label={`${NAV_ITEMS.find(n => n.id === currentView())?.label} view`}
      >
        <Suspense fallback={<LoadingFallback />}>
          <Dynamic component={VIEW_MAP[currentView()]} />
        </Suspense>
      </main>
    </div>
  );
}
