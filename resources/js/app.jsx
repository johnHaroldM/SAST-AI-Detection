import { createInertiaApp } from '@inertiajs/react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import '../css/app.css';

// The SAST JSON endpoints run under the `web` middleware group, so they are
// CSRF-protected. Triage posts go out through axios (not Inertia) to keep
// the review queue optimistic, which means axios needs the token itself.
axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';
axios.defaults.headers.common['X-CSRF-TOKEN'] =
  document.querySelector('meta[name="csrf-token"]')?.content ?? '';

// Page components live in `resources/js/pages` (lowercase). Globbing
// `./Pages/**` only resolved because Windows filesystems are
// case-insensitive — on the Linux CI runner it matched nothing and the app
// mounted an empty page map.
const pages = import.meta.glob('./pages/**/*.{jsx,tsx}', { eager: true });

createInertiaApp({
  resolve: (name) => {
    const page = pages[`./pages/${name}.jsx`] ?? pages[`./pages/${name}.tsx`];

    if (!page) {
      throw new Error(`Inertia page not found: ${name}`);
    }

    return page;
  },
  setup({ el, App, props }) {
    createRoot(el).render(<App {...props} />);
  },
});
