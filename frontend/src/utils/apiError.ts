import { isAxiosError } from "axios";

/** What kind of failure an error is, as far as the user is concerned. */
export type ErrorKind =
  | "offline"
  | "timeout"
  | "not_found"
  | "forbidden"
  | "rate_limited"
  | "server"
  | "unknown";

export interface DescribedError {
  kind: ErrorKind;
  /** HTTP status, when the server answered at all. */
  status: number | null;
  /** The server's `detail` message, when it sent one. */
  detail: string | null;
  /** Method and path of the failed request, for the technical details. */
  request: string | null;
  /** The raw message, for the technical details. */
  message: string | null;
}

const asText = (value: unknown): string | null => (typeof value === "string" && value.trim() ? value.trim() : null);

/** Sorts any thrown value into a kind the UI can explain. Never throws. */
export const describeError = (err: unknown): DescribedError => {
  if (isAxiosError(err)) {
    const status = err.response?.status ?? null;
    const data = err.response?.data as { detail?: unknown } | undefined;
    const method = err.config?.method?.toUpperCase();
    const url = err.config?.url;
    const base: Omit<DescribedError, "kind"> = {
      status,
      detail: asText(data?.detail),
      request: method && url ? `${method} ${url}` : url ?? null,
      message: asText(err.message),
    };
    if (status === null) {
      if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT") return { kind: "timeout", ...base };
      return { kind: "offline", ...base };
    }
    if (status === 404) return { kind: "not_found", ...base };
    if (status === 401 || status === 403) return { kind: "forbidden", ...base };
    if (status === 429) return { kind: "rate_limited", ...base };
    if (status === 408 || status === 504) return { kind: "timeout", ...base };
    if (status >= 500) return { kind: "server", ...base };
    return { kind: "unknown", ...base };
  }
  const message = err instanceof Error ? asText(err.message) : asText(err);
  return { kind: "unknown", status: null, detail: null, request: null, message };
};

type Translate = (english: string, german: string) => string;

/** One sentence on what happened and what helps, per kind. */
export const errorHint = (described: DescribedError, t: Translate): string => {
  const status = described.status ? ` (HTTP ${described.status})` : "";
  switch (described.kind) {
    case "offline":
      return t(
        "Hecate's backend did not answer. It may be restarting, or the network is down.",
        "Das Hecate-Backend hat nicht geantwortet. Es startet vielleicht gerade neu, oder das Netzwerk ist weg.",
      );
    case "timeout":
      return t(
        `The request took too long${status}. The server may be busy; try again in a moment.`,
        `Die Anfrage hat zu lange gedauert${status}. Der Server ist vielleicht ausgelastet; versuch es gleich noch einmal.`,
      );
    case "not_found":
      return t("This does not exist (any more).", "Das gibt es nicht (mehr).");
    case "forbidden":
      return t(
        `Access was refused${status}. A password may be missing or wrong.`,
        `Der Zugriff wurde verweigert${status}. Vielleicht fehlt ein Passwort oder es ist falsch.`,
      );
    case "rate_limited":
      return t(
        "Too many attempts in a short time. Wait a few minutes and try again.",
        "Zu viele Versuche in kurzer Zeit. Warte ein paar Minuten und versuch es dann erneut.",
      );
    case "server":
      return t(
        `The server ran into an error${status}. Trying again often helps; if not, the backend log says why.`,
        `Der Server hatte einen Fehler${status}. Ein neuer Versuch hilft oft; sonst steht der Grund im Backend-Log.`,
      );
    default:
      return t("Something unexpected went wrong.", "Etwas Unerwartetes ist schiefgelaufen.");
  }
};
