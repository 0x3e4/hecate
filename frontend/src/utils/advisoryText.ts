const OSV_BOILERPLATE = /^\s*-{3,}\s*$|^\s*_-=.*=-_\s*$/;
const OSV_SOURCE_HEADING = /^\s*#{1,6}\s*Source:.*$/;

/**
 * OSV's malicious-packages records open with a machine marker and per-source
 * headings (`_-= Per source details. Do not edit below this line.=-_`,
 * `## Source: ghsa-malware (<hash>)`). Display text starts at the first real
 * sentence; the stored record is untouched.
 */
export const cleanAdvisoryText = (text: string | null | undefined): string => {
  if (!text) return "";
  return text
    .split(/\r?\n/)
    .filter((line) => !OSV_BOILERPLATE.test(line) && !OSV_SOURCE_HEADING.test(line) && !/^\s*\([0-9a-f]{32,}\)\s*$/i.test(line))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
};

/**
 * OSV ecosystems can carry a registry URL (`Packagist:https://packages.drupal.org/8`).
 * Shows the ecosystem and the host instead of the raw string; display only.
 */
export const formatEcosystemName = (name: string): string => {
  const match = name.match(/^([^:]+):https?:\/\/([^/]+)/i);
  return match ? `${match[1]} (${match[2]})` : name;
};
