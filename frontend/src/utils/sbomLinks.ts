/** Normalize scanner-specific type names to canonical ecosystem names */
export const TYPE_ALIASES: Record<string, string> = {
  "node-pkg": "npm",
  "gobinary": "go",
  "jar": "maven",
  "pom": "maven",
  "python-pkg": "pypi",
  "dotnet-core": "nuget",
  "rust-crate": "cargo",
};

/** Map purl/type to deps.dev ecosystem name */
export const DEPS_DEV_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  nuget: "nuget",
  maven: "maven",
  golang: "go",
  go: "go",
  cargo: "cargo",
  gem: "rubygems",
  rubygems: "rubygems",
  composer: "packagist",
  packagist: "packagist",
};

/** Map purl/type to Snyk package type */
export const SNYK_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pip",
  nuget: "nuget",
  maven: "maven",
  golang: "golang",
  go: "golang",
  gem: "rubygems",
  rubygems: "rubygems",
  composer: "composer",
};

/** Map canonical ecosystem to socket.dev URL path segment */
export const SOCKET_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  go: "go",
  golang: "go",
  maven: "maven",
  nuget: "nuget",
  cargo: "cargo",
  gem: "gem",
  rubygems: "gem",
  composer: "packagist",
  packagist: "packagist",
};

/** Map canonical ecosystem to Aikido Intel URL path segment.
 *  Aikido's public Intel covers the same major ecosystems as socket.dev. */
export const AIKIDO_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  go: "go",
  golang: "go",
  maven: "maven",
  nuget: "nuget",
  cargo: "cargo",
  gem: "gem",
  rubygems: "gem",
  composer: "packagist",
  packagist: "packagist",
};

export function getEcosystemFromPurl(purl: string | null | undefined): string | null {
  if (!purl) return null;
  // purl format: pkg:<type>/<namespace>/<name>@<version>
  const match = purl.match(/^pkg:([^/]+)\//);
  return match ? match[1].toLowerCase() : null;
}

function resolveEcosystem(type: string, purl?: string | null): string {
  const raw = getEcosystemFromPurl(purl) ?? (type || "").toLowerCase();
  return TYPE_ALIASES[raw] ?? raw;
}

export function buildDepsDevUrl(name: string, version: string, type: string, purl?: string | null): string | null {
  const eco = resolveEcosystem(type, purl);
  const mapped = DEPS_DEV_ECOSYSTEM[eco];
  if (!mapped || !name) return null;
  // Omit the version segment when we don't know it (e.g. malware-feed cards
  // where targeting a specific version is misleading — the whole package is
  // suspect) or when the registry has retracted the version (the versioned
  // URL 404s on deps.dev). The package-level URL still lists all known
  // versions for the user to browse.
  if (!version) {
    return `https://deps.dev/${mapped}/${encodeURIComponent(name)}`;
  }
  return `https://deps.dev/${mapped}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

export function buildSnykUrl(name: string, version: string, type: string, purl?: string | null): string | null {
  const eco = resolveEcosystem(type, purl);
  const mapped = SNYK_ECOSYSTEM[eco];
  if (!mapped || !name) return null;
  // Same rationale as deps.dev — omit version for malware-feed / retracted
  // packages so the link lands on the package page instead of a 404.
  if (!version) {
    return `https://security.snyk.io/package/${mapped}/${encodeURIComponent(name)}`;
  }
  return `https://security.snyk.io/package/${mapped}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

/** Build a direct link to the package on its native registry */
export function buildRegistryUrl(name: string, version: string, type: string, purl?: string | null): { url: string; label: string } | null {
  const eco = resolveEcosystem(type, purl);
  if (!name) return null;
  const v = version ? encodeURIComponent(version) : "";
  const n = encodeURIComponent(name);
  switch (eco) {
    case "npm":
      return { url: `https://www.npmjs.com/package/${name}${v ? `/v/${v}` : ""}`, label: "npm" };
    case "pypi":
      return { url: `https://pypi.org/project/${n}/${v || ""}`, label: "PyPI" };
    case "maven": {
      // Maven purl: pkg:maven/group/artifact — name may contain the group
      const parts = name.split("/");
      if (parts.length === 2) {
        return { url: `https://central.sonatype.com/artifact/${parts[0]}/${parts[1]}${v ? `/${v}` : ""}`, label: "Maven" };
      }
      return { url: `https://central.sonatype.com/search?q=${n}`, label: "Maven" };
    }
    case "go":
    case "golang":
      return { url: `https://pkg.go.dev/${name}${v ? `@${v}` : ""}`, label: "Go" };
    case "nuget":
      return { url: `https://www.nuget.org/packages/${n}${v ? `/${v}` : ""}`, label: "NuGet" };
    case "cargo":
      return { url: `https://crates.io/crates/${n}${v ? `/${v}` : ""}`, label: "crates.io" };
    case "gem":
      return { url: `https://rubygems.org/gems/${n}${v ? `/versions/${v}` : ""}`, label: "RubyGems" };
    case "composer":
    case "packagist":
      return { url: `https://packagist.org/packages/${name}`, label: "Packagist" };
    case "cocoapods":
      return { url: `https://cocoapods.org/pods/${n}`, label: "CocoaPods" };
    case "hex":
      return { url: `https://hex.pm/packages/${n}${v ? `/${v}` : ""}`, label: "Hex" };
    case "pub":
      return { url: `https://pub.dev/packages/${n}${v ? `/versions/${v}` : ""}`, label: "pub.dev" };
    case "swift":
      return { url: `https://swiftpackageindex.com/search?query=${n}`, label: "Swift" };
    case "docker":
    case "oci":
      // Docker Hub or generic registry
      if (!name.includes(".") && !name.includes(":")) {
        const dockerName = name.includes("/") ? name : `library/${name}`;
        return { url: `https://hub.docker.com/r/${dockerName}`, label: "Docker Hub" };
      }
      return null;
    default:
      return null;
  }
}

/** Build a socket.dev supply-chain score URL. Multi-ecosystem; version is not
 *  included because the socket.dev package page already exposes per-version
 *  data. Package names are passed literally — socket.dev's canonical URLs use
 *  unencoded '@' and '/' (e.g. `/npm/package/@bitwarden/cli`,
 *  `/go/package/cel.dev/expr`); the %-encoded forms 404 on their router. */
export function buildSocketUrl(name: string, _version: string, type: string, purl?: string | null): string | null {
  const eco = resolveEcosystem(type, purl);
  const mapped = SOCKET_ECOSYSTEM[eco];
  if (!mapped || !name) return null;
  return `https://socket.dev/${mapped}/package/${name}`;
}

/** Build an Aikido Intel package URL. Multi-ecosystem; version is not included
 *  (the page exposes per-version data). Same literal-slash rule as socket.dev
 *  — Aikido's canonical URLs use `/packages/{eco}/{name}` with unencoded '@'
 *  and '/' (e.g. `/packages/npm/@bitwarden/cli`). */
export function buildAikidoUrl(name: string, _version: string, type: string, purl?: string | null): string | null {
  const eco = resolveEcosystem(type, purl);
  const mapped = AIKIDO_ECOSYSTEM[eco];
  if (!mapped || !name) return null;
  return `https://intel.aikido.dev/packages/${mapped}/${name}`;
}

/** Build a bundlephobia.com URL. npm-only. */
export function buildBundlephobiaUrl(name: string, version: string, type: string, purl?: string | null): string | null {
  const eco = resolveEcosystem(type, purl);
  if (eco !== "npm" || !name) return null;
  return `https://bundlephobia.com/package/${name}${version ? `@${version}` : ""}`;
}

/** Build an npmgraph.js.org URL. npm-only. Uses %40 as the name@version separator
 *  to mirror the canonical npmgraph query-string format. */
export function buildNpmGraphUrl(name: string, version: string, type: string, purl?: string | null): string | null {
  const eco = resolveEcosystem(type, purl);
  if (eco !== "npm" || !name) return null;
  const q = version ? `${encodeURIComponent(name)}%40${encodeURIComponent(version)}` : encodeURIComponent(name);
  return `https://npmgraph.js.org/?q=${q}`;
}

