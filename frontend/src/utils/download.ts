/** Byte order mark, so Excel opens a UTF-8 CSV with umlauts intact. */
const UTF8_BOM = String.fromCharCode(0xfeff);

/** Save a downloaded blob (a server export) as a file. */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/** Save a text payload as a file through a temporary object URL. */
export function downloadText(content: string, filename: string, mime: string): void {
  const parts = mime.startsWith("text/csv") ? [UTF8_BOM, content] : [content];
  const url = URL.createObjectURL(new Blob(parts, { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
