export function manualChunks(id: string) {
  if (id.includes('node_modules')) {
    if (id.includes('react-select')) return 'react-select';
    if (id.includes('react-icons')) return 'react-icons';
    if (id.includes('react-router-dom')) return 'react-router';
    if (id.includes('axios')) return 'axios';
    if (id.includes('react')) return 'react';
    return 'vendor';
  }
}
