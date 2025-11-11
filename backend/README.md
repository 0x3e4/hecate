# Hecate Backend

FastAPI-Service zum Erfassen, Anreichern und Bereitstellen von Schwachstelleninformationen. Die Dokumentation für das Gesamtprojekt befindet sich in der README im Repository-Root.

## Entwicklung

### Abhängigkeiten verwalten

Dieses Projekt verwendet [Poetry](https://python-poetry.org/) für die Verwaltung von Abhängigkeiten.

#### Neue Abhängigkeit hinzufügen

```bash
# pyproject.toml manuell bearbeiten und dann die Lock-Datei aktualisieren:
docker compose run --rm backend-build -c "poetry lock"

# Oder direkt mit Poetry hinzufügen:
docker compose run --rm backend-build -c "poetry add <paket-name>"

# Dann beide Dateien committen:
git add pyproject.toml poetry.lock
git commit -m "Add <paket-name> dependency"
```

#### Abhängigkeiten aktualisieren

```bash
# Alle Abhängigkeiten auf die neuesten kompatiblen Versionen aktualisieren:
docker compose run --rm backend-build -c "poetry update"

# Ein bestimmtes Paket aktualisieren:
docker compose run --rm backend-build -c "poetry update <paket-name>"

# Dann die Änderungen committen:
git add poetry.lock
git commit -m "Update dependencies"
```

#### Abhängigkeiten lokal installieren

```bash
# Falls Poetry lokal installiert ist:
poetry install

# Oder mit Docker:
docker compose run --rm backend-build -c "poetry install"
```

### Warum poetry.lock wichtig ist

Die Datei `poetry.lock` stellt sicher:
- **Reproduzierbare Builds** - Alle verwenden die gleichen Abhängigkeitsversionen
- **Sicherheitsprüfung** - Trivy scannt diese Datei auf Schwachstellen
- **Supply-Chain-Sicherheit** - Fixiert exakte Versionen zur Verhinderung von Angriffen

Committe `poetry.lock` immer in die Versionsverwaltung.
