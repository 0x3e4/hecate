export function manualChunks(id: string) {
  if (id.includes('node_modules')) {
    if (id.includes('react-select')) return 'react-select';
    if (id.includes('react-icons')) return 'react-icons';
    if (id.includes('axios')) return 'axios';
    return 'vendor';
  }
}
