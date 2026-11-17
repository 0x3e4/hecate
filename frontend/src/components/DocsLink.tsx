import type { ReactNode } from "react";

import { useServerConfig } from "../server-config/context";
import { ExternalLink } from "../ui/primitives";
import { docsHref } from "../utils/docsHref";

/**
 * A link to a page of the documentation site. Explanations live there, the UI
 * keeps one short line and this link. Renders nothing when no docs URL is set.
 */
export const DocsLink = ({ path, children, className }: { path: string; children: ReactNode; className?: string }) => {
  const { docsUrl } = useServerConfig();
  const href = docsHref(docsUrl, path);
  if (!href) return null;
  return (
    <ExternalLink href={href} className={className}>
      {children}
    </ExternalLink>
  );
};
