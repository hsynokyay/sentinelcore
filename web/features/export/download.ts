/**
 * Triggers a browser download of a text blob as a file.
 */
export function downloadAsFile(
  content: string,
  filename: string,
  mimeType = "text/markdown",
): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Generates a safe filename from a finding or scan title.
 */
export function safeFilename(title: string, suffix: string): string {
  const base = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60);
  return `${base}${suffix}`;
}
