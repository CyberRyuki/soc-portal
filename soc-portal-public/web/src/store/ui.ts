import { create } from 'zustand';

export type Theme = 'light' | 'dark' | 'xr';
const THEMES: Theme[] = ['light', 'dark', 'xr'];
const KEY = 'soc-theme';

function initialTheme(): Theme {
  try {
    const t = localStorage.getItem(KEY);
    if (t && (THEMES as string[]).includes(t)) return t as Theme;
  } catch {
    /* almacenamiento no disponible */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function apply(t: Theme) {
  document.documentElement.dataset.theme = t;
}

interface UiState {
  theme: Theme;
  /** tema anterior mientras la vista NOC fuerza el XR */
  themeBeforeNoc: Theme | null;
  sidebarOpen: boolean;
  setTheme: (t: Theme) => void;
  cycleTheme: () => void;
  enterNoc: () => void;
  leaveNoc: () => void;
  setSidebar: (open: boolean) => void;
}

export const useUi = create<UiState>((set, get) => {
  const t0 = initialTheme();
  apply(t0);
  return {
    theme: t0,
    themeBeforeNoc: null,
    sidebarOpen: false,
    setTheme: (theme) => {
      apply(theme);
      try {
        localStorage.setItem(KEY, theme);
      } catch {
        /* ignorar */
      }
      set({ theme });
    },
    cycleTheme: () => {
      const cur = get().theme;
      get().setTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length] ?? 'light');
    },
    enterNoc: () => {
      const { theme } = get();
      apply('xr');
      set({ themeBeforeNoc: theme, theme: 'xr' });
    },
    leaveNoc: () => {
      const prev = get().themeBeforeNoc;
      if (prev) {
        apply(prev);
        set({ theme: prev, themeBeforeNoc: null });
      }
    },
    setSidebar: (sidebarOpen) => set({ sidebarOpen }),
  };
});

export const THEME_LABEL: Record<Theme, string> = { light: 'Claro', dark: 'Oscuro', xr: 'XR' };
