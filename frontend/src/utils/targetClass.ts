/** What a scan target is and whether the internet reaches it (see docs/sca/hosts.md). */

export type TargetKind = "host" | "kubernetes-node" | "container" | "other";
export type TargetExposure = "internet" | "internal";

type Translate = (en: string, de: string) => string;

export const TARGET_KINDS: TargetKind[] = ["host", "kubernetes-node", "container", "other"];

export const kindLabel = (kind: TargetKind | string, t: Translate): string => {
  switch (kind) {
    case "host":
      return t("Host", "Host");
    case "kubernetes-node":
      return t("Kubernetes node", "Kubernetes-Node");
    case "container":
      return t("Container", "Container");
    default:
      return t("Other", "Sonstiges");
  }
};

export const exposureLabel = (exposure: TargetExposure | string, t: Translate): string =>
  exposure === "internet" ? t("Internet-facing", "Aus dem Internet erreichbar") : t("Internal only", "Nur intern");

/**
 * The chips a target row shows: internet-facing first (it is the reason to look),
 * then the kind. "Internal" and unknown add nothing to a row.
 */
export const targetClassChips = (
  kind: string | null | undefined,
  exposure: string | null | undefined,
  t: Translate,
): { key: string; label: string; title: string; exposed: boolean }[] => {
  const chips: { key: string; label: string; title: string; exposed: boolean }[] = [];
  // Short on the chip (it sits next to the name, with a globe), in full as its title.
  if (exposure === "internet") {
    chips.push({ key: "exposure", label: "Internet", title: exposureLabel("internet", t), exposed: true });
  }
  if (kind) chips.push({ key: "kind", label: kindLabel(kind, t), title: kindLabel(kind, t), exposed: false });
  return chips;
};
