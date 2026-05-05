// Mermaid + its exclusive transitive deps. Do NOT bucket them into "vendor"
// — letting `manualChunks` return undefined for these IDs lets Rollup pull
// them into the async chunk created by `import("mermaid")`, which keeps them
// out of the initial modulepreload list.
const MERMAID_EXCLUSIVE = /node_modules\/(?:\.pnpm\/)?(?:mermaid|@mermaid-js|cytoscape(?:-cose-bilkent|-fcose)?|cose-base|d3|d3-[^/]+|dagre|dagre-d3-es|katex|khroma|roughjs|ts-dedent|@braintree\/sanitize-url|@iconify[^/]*|@upsetjs[^/]*|dompurify|marked|chevrotain|chevrotain-allstar|@chevrotain[^/]*|robust-predicates|delaunator|internmap|fflate|kdbush|debounce|hachure-fill|points-on-curve|points-on-path|path-data-parser|path-browserify|lodash-es|dayjs|langium|vscode-(?:languageserver|jsonrpc|uri))(?:@|\/)/;

export function manualChunks(id: string) {
  if (id.includes('node_modules')) {
    if (MERMAID_EXCLUSIVE.test(id)) return undefined;
    if (id.includes('react-select')) return 'react-select';
    if (id.includes('react-icons')) return 'react-icons';
    if (id.includes('axios')) return 'axios';
    return 'vendor';
  }
  return undefined;
}
