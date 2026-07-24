module.exports = {
  content: [
    './index.html',
    './src/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        surface: '#0b1221',
        panel: '#111828',
        border: '#1f2a44',
        danger: '#ff4d6d',
        safe: '#10b981',
        warn: '#f59e0b',
        text: '#e2e8f0',
      },
      boxShadow: {
        glow: '0 20px 80px rgba(15, 23, 42, 0.35)',
      },
    },
  },
  plugins: [],
};
