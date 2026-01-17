import { createSignal, lazy, Suspense, For } from 'solid-js';
import { Dynamic } from 'solid-js/web';

// Lazy load views
const Dashboard = lazy(() => import('./views/Dashboard'));
const Analyze = lazy(() => import('./views/Analyze'));

type View = 'dashboard' | 'analyze' | 'search' | 'monitor' | 'settings';

interface NavItem {
  id: View;
  label: string;
  icon: string;
}

const navItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
  { id: 'analyze', label: 'Analyze', icon: '🔍' },
  { id: 'search', label: 'NVD Search', icon: '🌐' },
  { id: 'monitor', label: 'Monitor', icon: '📡' },
  { id: 'settings', label: 'Settings', icon: '⚙️' },
];

function Sidebar(props: { current: View; onNavigate: (view: View) => void }) {
  return (
    <aside class="w-56 bg-surface border-r border-border flex flex-col">
      {/* Logo */}
      <div class="p-4 border-b border-border">
        <h1 class="text-lg font-bold text-accent">Driver Search</h1>
        <p class="text-xs text-text-muted">Vulnerable Driver Research</p>
      </div>

      {/* Navigation */}
      <nav class="flex-1 p-2">
        <For each={navItems}>
          {(item) => (
            <button
              onClick={() => props.onNavigate(item.id)}
              class={`w-full px-3 py-2 rounded text-left flex items-center gap-2 transition-colors
                ${props.current === item.id 
                  ? 'bg-accent/10 text-accent' 
                  : 'text-text-muted hover:text-text hover:bg-surface-raised'
                }`}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          )}
        </For>
      </nav>

      {/* Footer */}
      <div class="p-4 border-t border-border text-xs text-text-dim">
        <p>v0.1.0</p>
      </div>
    </aside>
  );
}

function PlaceholderView(props: { name: string }) {
  return (
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-4">{props.name}</h1>
      <p class="text-text-muted">This view is under construction.</p>
    </div>
  );
}

export default function App() {
  const [currentView, setCurrentView] = createSignal<View>('dashboard');

  const viewComponent = () => {
    switch (currentView()) {
      case 'dashboard':
        return Dashboard;
      case 'analyze':
        return Analyze;
      case 'search':
        return () => <PlaceholderView name="NVD Search" />;
      case 'monitor':
        return () => <PlaceholderView name="Monitor" />;
      case 'settings':
        return () => <PlaceholderView name="Settings" />;
      default:
        return Dashboard;
    }
  };

  return (
    <div class="flex h-screen bg-background">
      <Sidebar current={currentView()} onNavigate={setCurrentView} />
      
      <main class="flex-1 overflow-auto">
        <Suspense fallback={
          <div class="flex items-center justify-center h-full text-text-muted">
            Loading...
          </div>
        }>
          <Dynamic component={viewComponent()} />
        </Suspense>
      </main>
    </div>
  );
}
