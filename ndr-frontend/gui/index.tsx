
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { initRuntimeConfig } from './config';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

// Fetch APP_MODE from the live backend before mounting the React tree.
// This ensures CONFIG.APP_MODE is correct at runtime without requiring a rebuild.
initRuntimeConfig().finally(() => {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
});
