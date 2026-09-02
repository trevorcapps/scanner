import type { Config } from 'tailwindcss';

/** Colors reference "R G B" CSS variables (src/index.css, dark + light).
 *  rgb(var(--x) / <alpha-value>) lets the /opacity modifier work. */
const withVar = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: withVar('bg'),
        surface: withVar('surface'),
        raised: withVar('surface-raised'),
        hover: withVar('surface-hover'),
        line: withVar('line'),
        'line-soft': withVar('line-soft'),
        text: withVar('text'),
        'text-soft': withVar('text-soft'),
        muted: withVar('muted'),
        faint: withVar('faint'),
        blue: withVar('blue'),
        cyan: withVar('cyan'),
        lime: withVar('lime'),
        magenta: withVar('magenta'),
        amber: withVar('amber'),
        danger: withVar('danger'),
        'danger-bg': withVar('danger-bg'),
        critical: withVar('danger'),
        high: withVar('amber'),
        medium: withVar('blue'),
        low: withVar('cyan'),
        info: withVar('muted'),
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Cascadia Code"', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      boxShadow: {
        panel: '0 1px 2px rgb(var(--shadow) / 0.4), 0 8px 24px -12px rgb(var(--shadow) / 0.5)',
      },
      borderRadius: {
        DEFAULT: '4px',
      },
    },
  },
  plugins: [],
} satisfies Config;
