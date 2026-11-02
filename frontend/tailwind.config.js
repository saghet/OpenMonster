/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0d14',
          card: '#111726',
          border: '#1f293d',
          accent: '#00f0ff',
          neon: '#10b981',
          danger: '#ef4444',
          warning: '#f59e0b',
          muted: '#64748b'
        }
      }
    },
  },
  plugins: [],
}
