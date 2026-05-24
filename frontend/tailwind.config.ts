import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: 'class',
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['DM Sans', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
        display: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        // Surfaces (very dark, layered)
        ink: {
          950: '#05080d',
          900: '#0a0e14',
          850: '#0d1219',
          800: '#11161e',
          750: '#161c26',
          700: '#1d242f',
          600: '#2a323e',
        },
        // Text
        bone: {
          50: '#f5f7fa',
          100: '#e8ecf0',
          200: '#c7cfd9',
          300: '#9aa5b3',
          400: '#7a8493',
          500: '#5b6573',
        },
        // Signal palette
        signal: {
          DEFAULT: '#22d3ee',  // electric cyan
          50: '#ecfeff',
          100: '#cffafe',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
        },
        warn: '#fbbf24',     // amber
        danger: '#f87171',   // coral
        critical: '#ef4444', // red
        ok: '#a3e635',       // lime
      },
      backgroundImage: {
        'grid-faint': "linear-gradient(rgba(34,211,238,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(34,211,238,0.05) 1px, transparent 1px)",
        'scan-glow': "radial-gradient(circle at 50% 0%, rgba(34,211,238,0.15), transparent 70%)",
      },
      backgroundSize: {
        'grid-32': '32px 32px',
        'grid-64': '64px 64px',
      },
      boxShadow: {
        'signal-glow': '0 0 24px -4px rgba(34,211,238,0.4)',
        'inset-line': 'inset 0 0 0 1px rgba(34,211,238,0.15)',
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scan-line': 'scan-line 4s linear infinite',
        'fade-up': 'fade-up 0.5s ease-out',
      },
      keyframes: {
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};

export default config;
