/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{html,ts}",
  ],
  theme: {
    extend: {
      colors: {
        surface: '#070e1d',
        'surface-container-low': '#0b1323',
        'surface-container-highest': '#1b263b',
        primary: '#69f6b8',
        secondary: '#f8a010',
        tertiary: '#ff716a',
        'on-surface-variant': '#a4abbf',
        outline: '#6e7588',
        'error': '#ff716c',
        'error-container': '#9f0519',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        display: ['Space Grotesk', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
