"""Dependency scope (runtime / optional / dev) read from lockfiles and manifests."""
from __future__ import annotations

import json
from pathlib import Path

from app import hecate_analyzer as ha


def _scopes(components: list[dict]) -> dict[tuple[str, str], str | None]:
    return {(c["name"], c.get("version", "")): ha._component_scope(c) for c in components}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------- helpers


def test_merge_rule_runtime_wins_and_unknown_never_overrides() -> None:
    assert ha._merge_scope("dev", "runtime") == "runtime"
    assert ha._merge_scope("runtime", "dev") == "runtime"
    assert ha._merge_scope("dev", "optional") == "optional"
    assert ha._merge_scope("dev", None) == "dev"
    assert ha._merge_scope(None, None) is None


def test_scope_is_written_as_property_and_cyclonedx_scope() -> None:
    comp = ha._lib_component("x", "1", "pkg:npm/x@1", "package.json", "dev")
    assert comp["scope"] == "excluded"
    assert {"name": "hecate:scope", "value": "dev"} in comp["properties"]
    assert "scope" not in ha._lib_component("x", "1", "pkg:npm/x@1", "package.json")


def test_propagation_keeps_the_best_scope_over_all_paths() -> None:
    edges = {"app": [("shared", False), ("opt", True)], "tool": [("shared", False), ("toolonly", False)]}
    scopes = ha._propagate_scopes({"app": "runtime", "tool": "dev"}, edges)
    assert scopes == {"app": "runtime", "shared": "runtime", "opt": "optional", "tool": "dev", "toolonly": "dev"}


# ---------------------------------------------------------------- npm


def test_package_lock_flags(tmp_path: Path) -> None:
    _write(tmp_path / "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/express": {"version": "4.21.0"},
            "node_modules/vitest": {"version": "3.0.0", "dev": True},
            "node_modules/fsevents": {"version": "2.3.3", "optional": True},
            "node_modules/esbuild-x": {"version": "0.1.0", "devOptional": True},
            # the same version reached as dev elsewhere stays runtime
            "node_modules/vitest/node_modules/express": {"version": "4.21.0", "dev": True},
        },
    }))
    scopes = _scopes(ha.parse_package_lock_json(str(tmp_path)))
    assert scopes == {
        ("express", "4.21.0"): "runtime",
        ("vitest", "3.0.0"): "dev",
        ("fsevents", "2.3.3"): "optional",
        ("esbuild-x", "0.1.0"): "optional",
    }


def test_package_lock_v1_legacy_tree(tmp_path: Path) -> None:
    _write(tmp_path / "package-lock.json", json.dumps({
        "lockfileVersion": 1,
        "dependencies": {"left-pad": {"version": "1.3.0"}, "mocha": {"version": "10.0.0", "dev": True}},
    }))
    assert _scopes(ha.parse_package_lock_json(str(tmp_path))) == {
        ("left-pad", "1.3.0"): "runtime", ("mocha", "10.0.0"): "dev",
    }


def test_package_json_sections_without_lockfile(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", json.dumps({
        "dependencies": {"react": "18.3.1"},
        "devDependencies": {"typescript": "5.9.0"},
        "optionalDependencies": {"sharp": "0.33.0"},
    }))
    assert _scopes(ha.parse_package_jsons(str(tmp_path))) == {
        ("react", "18.3.1"): "runtime", ("typescript", "5.9.0"): "dev", ("sharp", "0.33.0"): "optional",
    }


YARN_V1 = '''# yarn lockfile v1


express@^4.21.0:
  version "4.21.0"
  resolved "https://registry.yarnpkg.com/express/-/express-4.21.0.tgz"
  dependencies:
    debug "2.6.9"

debug@2.6.9:
  version "2.6.9"

jest@^29.0.0:
  version "29.7.0"
  dependencies:
    "@jest/core" "^29.7.0"
    debug "2.6.9"

"@jest/core@^29.7.0":
  version "29.7.0"

orphan@^1.0.0:
  version "1.0.0"
'''


def test_yarn_classic_scope_from_package_json_and_graph(tmp_path: Path) -> None:
    _write(tmp_path / "yarn.lock", YARN_V1)
    _write(tmp_path / "package.json", json.dumps({
        "dependencies": {"express": "^4.21.0"}, "devDependencies": {"jest": "^29.0.0"},
    }))
    scopes = _scopes(ha.parse_yarn_lock(str(tmp_path)))
    assert scopes[("express", "4.21.0")] == "runtime"
    assert scopes[("debug", "2.6.9")] == "runtime"  # runtime path beats the dev one
    assert scopes[("jest", "29.7.0")] == "dev"
    assert scopes[("@jest/core", "29.7.0")] == "dev"
    assert scopes[("orphan", "1.0.0")] is None  # unreachable: the lockfile says nothing


def test_yarn_without_package_json_stays_unknown(tmp_path: Path) -> None:
    _write(tmp_path / "yarn.lock", YARN_V1)
    assert set(_scopes(ha.parse_yarn_lock(str(tmp_path))).values()) == {None}


def test_yarn_berry(tmp_path: Path) -> None:
    _write(tmp_path / "yarn.lock", '''__metadata:
  version: 8

"lodash@npm:^4.17.21":
  version: 4.17.21

"eslint@npm:^9.0.0":
  version: 9.1.0
  dependencies:
    lodash: "npm:^4.17.21"
''')
    _write(tmp_path / "package.json", json.dumps({"devDependencies": {"eslint": "^9.0.0"}}))
    assert _scopes(ha.parse_yarn_lock(str(tmp_path))) == {("lodash", "4.17.21"): "dev", ("eslint", "9.1.0"): "dev"}


def test_pnpm_v6_flags(tmp_path: Path) -> None:
    _write(tmp_path / "pnpm-lock.yaml", '''lockfileVersion: '6.0'
packages:
  /react@18.3.1:
    dev: false
  /vite@7.0.0:
    dev: true
  /fsevents@2.3.3:
    dev: false
    optional: true
  /string_decoder@1.3.0:
    dev: false
''')
    assert _scopes(ha.parse_pnpm_lock_yaml(str(tmp_path))) == {
        ("react", "18.3.1"): "runtime", ("vite", "7.0.0"): "dev",
        ("fsevents", "2.3.3"): "optional", ("string_decoder", "1.3.0"): "runtime",
    }


def test_pnpm_v9_graph(tmp_path: Path) -> None:
    _write(tmp_path / "pnpm-lock.yaml", '''lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.3.1
        version: 18.3.1(react@18.3.1)
    devDependencies:
      vitest:
        specifier: ^3.0.0
        version: 3.0.0
packages:
  react-dom@18.3.1:
    resolution: {integrity: sha512-x}
  react@18.3.1:
    resolution: {integrity: sha512-y}
  vitest@3.0.0:
    resolution: {integrity: sha512-z}
  tinyspy@3.0.0:
    resolution: {integrity: sha512-w}
snapshots:
  react-dom@18.3.1(react@18.3.1):
    dependencies:
      react: 18.3.1
  react@18.3.1: {}
  vitest@3.0.0:
    dependencies:
      tinyspy: 3.0.0
  tinyspy@3.0.0: {}
''')
    assert _scopes(ha.parse_pnpm_lock_yaml(str(tmp_path))) == {
        ("react-dom", "18.3.1"): "runtime", ("react", "18.3.1"): "runtime",
        ("vitest", "3.0.0"): "dev", ("tinyspy", "3.0.0"): "dev",
    }


def test_pnpm_key_parsing() -> None:
    assert ha._pnpm_name_and_version("/@babel/core/7.12.3_react@18.0.0") == ("@babel/core", "7.12.3")
    assert ha._pnpm_name_and_version("/lodash/4.17.21") == ("lodash", "4.17.21")
    assert ha._pnpm_name_and_version("@babel/core@7.12.3(react@18)") == ("@babel/core", "7.12.3")
    assert ha._pnpm_name_and_version("string_decoder@1.3.0") == ("string_decoder", "1.3.0")


def test_bun_lock_graph(tmp_path: Path) -> None:
    _write(tmp_path / "bun.lock", '''{
  "lockfileVersion": 1,
  "workspaces": {"": {"dependencies": {"hono": "^4"}, "devDependencies": {"typescript": "^5"}}},
  "packages": {
    "hono": ["hono@4.6.0", "", {"dependencies": {"tiny": "^1"}}, "sha512-a"],
    "tiny": ["tiny@1.0.0", "", {}, "sha512-b"],
    "typescript": ["typescript@5.9.0", "", {}, "sha512-c"],
  }
}''')
    assert _scopes(ha.parse_bun_lock(str(tmp_path))) == {
        ("hono", "4.6.0"): "runtime", ("tiny", "1.0.0"): "runtime", ("typescript", "5.9.0"): "dev",
    }


# ---------------------------------------------------------------- Python


def test_pipfile_lock_sections(tmp_path: Path) -> None:
    _write(tmp_path / "Pipfile.lock", json.dumps({
        "default": {"requests": {"version": "==2.32.0"}},
        "develop": {"pytest": {"version": "==8.0.0"}, "requests": {"version": "==2.32.0"}},
    }))
    assert _scopes(ha.parse_pipfile_lock(str(tmp_path))) == {
        ("requests", "2.32.0"): "runtime", ("pytest", "8.0.0"): "dev",
    }


def test_poetry_lock_groups_and_category(tmp_path: Path) -> None:
    _write(tmp_path / "poetry.lock", '''
[[package]]
name = "fastapi"
version = "0.139.0"
groups = ["main"]

[[package]]
name = "pytest"
version = "8.0.0"
groups = ["dev"]

[[package]]
name = "uvloop"
version = "0.21.0"
optional = true
groups = ["main"]

[[package]]
name = "black"
version = "24.0.0"
category = "dev"

[[package]]
name = "mystery"
version = "1.0"
''')
    assert _scopes(ha.parse_poetry_lock(str(tmp_path))) == {
        ("fastapi", "0.139.0"): "runtime", ("pytest", "8.0.0"): "dev", ("uvloop", "0.21.0"): "optional",
        ("black", "24.0.0"): "dev", ("mystery", "1.0"): None,
    }


def test_uv_lock_graph(tmp_path: Path) -> None:
    _write(tmp_path / "uv.lock", '''
version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "httpx" }]

[package.optional-dependencies]
fast = [{ name = "orjson" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "httpx"
version = "0.28.0"
dependencies = [{ name = "anyio" }]

[[package]]
name = "anyio"
version = "4.0.0"

[[package]]
name = "orjson"
version = "3.10.0"

[[package]]
name = "pytest"
version = "8.0.0"
dependencies = [{ name = "anyio" }]
''')
    assert _scopes(ha.parse_uv_lock(str(tmp_path))) == {
        ("httpx", "0.28.0"): "runtime", ("anyio", "4.0.0"): "runtime",
        ("orjson", "3.10.0"): "optional", ("pytest", "8.0.0"): "dev",
    }


# ---------------------------------------------------------------- PHP, Java, .NET, Dart


def test_composer_lock_sections(tmp_path: Path) -> None:
    _write(tmp_path / "composer.lock", json.dumps({
        "packages": [{"name": "symfony/http-kernel", "version": "v7.1.0"}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "11.0.0"}],
    }))
    assert _scopes(ha.parse_composer(str(tmp_path))) == {
        ("symfony/http-kernel", "7.1.0"): "runtime", ("phpunit/phpunit", "11.0.0"): "dev",
    }


def test_pom_scopes(tmp_path: Path) -> None:
    _write(tmp_path / "pom.xml", '''<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency><groupId>org.a</groupId><artifactId>core</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.a</groupId><artifactId>servlet</artifactId><version>1.0</version><scope>provided</scope></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
    <dependency><groupId>org.a</groupId><artifactId>extra</artifactId><version>1.0</version><optional>true</optional></dependency>
  </dependencies>
</project>''')
    assert _scopes(ha.parse_pom_xml(str(tmp_path))) == {
        ("org.a:core", "1.0"): "runtime", ("org.a:servlet", "1.0"): "runtime",
        ("junit:junit", "4.13"): "dev", ("org.a:extra", "1.0"): "optional",
    }


def test_gradle_lockfile_configurations(tmp_path: Path) -> None:
    _write(tmp_path / "gradle.lockfile", "\n".join([
        "# Gradle lockfile",
        "com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath,testRuntimeClasspath",
        "org.junit.jupiter:junit-jupiter:5.10.0=testCompileClasspath,testRuntimeClasspath",
        "com.google.errorprone:error_prone_core:2.0=annotationProcessor",
        "empty=",
    ]))
    assert _scopes(ha.parse_gradle_lockfile(str(tmp_path))) == {
        ("com.google.guava:guava", "33.0.0-jre"): "runtime",
        ("org.junit.jupiter:junit-jupiter", "5.10.0"): "dev",
        ("com.google.errorprone:error_prone_core", "2.0"): "dev",
    }


def test_dotnet_private_assets_and_test_projects(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "App.csproj", '''<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="4.0.0" />
    <PackageReference Include="StyleCop.Analyzers" Version="1.1.118" PrivateAssets="all" />
  </ItemGroup>
</Project>''')
    _write(tmp_path / "tests" / "App.Tests.csproj", '''<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.0.0" />
    <PackageReference Include="xunit" Version="2.9.0" />
  </ItemGroup>
</Project>''')
    scopes = _scopes(ha.parse_dotnet(str(tmp_path)))
    assert scopes[("Serilog", "4.0.0")] == "runtime"
    assert scopes[("StyleCop.Analyzers", "1.1.118")] == "dev"
    assert scopes[("xunit", "2.9.0")] == "dev"


def test_pubspec_lock_dependency_kind(tmp_path: Path) -> None:
    _write(tmp_path / "pubspec.lock", '''packages:
  http:
    dependency: "direct main"
    version: "1.2.0"
  test:
    dependency: "direct dev"
    version: "1.25.0"
  async:
    dependency: transitive
    version: "2.11.0"
''')
    assert _scopes(ha.parse_pubspec(str(tmp_path))) == {
        ("http", "1.2.0"): "runtime", ("test", "1.25.0"): "dev", ("async", "2.11.0"): None,
    }


# ---------------------------------------------------------------- envelope


def test_run_analysis_merges_scope_of_duplicates(tmp_path: Path) -> None:
    _write(tmp_path / "a" / "package-lock.json", json.dumps({
        "lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.21", "dev": True}},
    }))
    _write(tmp_path / "b" / "package-lock.json", json.dumps({
        "lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.21"}},
    }))
    components = ha.run_analysis(str(tmp_path))["components"]
    lodash = [c for c in components if c["name"] == "lodash"]
    assert len(lodash) == 1
    assert ha._component_scope(lodash[0]) == "runtime"
    assert lodash[0]["scope"] == "required"
