import { LuGlobe } from "react-icons/lu";

import { useI18n } from "../i18n/context";
import { targetClassChips } from "../utils/targetClass";

/** "Internet-facing" and the kind (host, Kubernetes node, …) of a scan target. */
export const TargetClassChips = ({ kind, exposure }: { kind?: string | null; exposure?: string | null }) => {
  const { t } = useI18n();
  const chips = targetClassChips(kind, exposure, t);
  if (chips.length === 0) return null;
  return (
    <span className="target-class-chips">
      {chips.map((chip) => (
        <span key={chip.key} className={chip.exposed ? "chip target-class-exposed" : "chip"}>
          {chip.exposed && <LuGlobe aria-hidden="true" />}
          {chip.label}
        </span>
      ))}
    </span>
  );
};
