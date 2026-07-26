/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './resources/js/**/*.jsx',
    './resources/views/**/*.blade.php',
  ],
  theme: {
    extend: {
      colors: {
        ink: '#10131A',        // page background
        panel: '#191E29',      // card/surface
        'panel-raised': '#212736',
        hairline: '#2A3140',   // borders
        paper: '#EDEFF4',      // primary text
        fog: '#8B93A7',        // muted text
        amber: '#E8A33D',      // pending triage
        'signal-red': '#E5484D',   // true positive
        'signal-green': '#45B08C', // false positive
        sev: {
          critical: '#FF5D5D',
          high: '#F2994A',
          medium: '#E8C547',
          low: '#6B93C9',
        },
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'sans-serif'],
        sans: ['Inter', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
};
