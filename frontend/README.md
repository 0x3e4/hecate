# Hecate Frontend

React-Anwendung für die Visualisierung und Verwaltung von Schwachstelleninformationen. Die Dokumentation für das Gesamtprojekt befindet sich in der README im Repository-Root.

## Entwicklung

### Abhängigkeiten verwalten

Dieses Projekt verwendet [npm](https://www.npmjs.com/) für die Verwaltung von Abhängigkeiten.

#### Neue Abhängigkeit hinzufügen

```bash
# Abhängigkeit hinzufügen (package-lock.json wird automatisch aktualisiert):
docker compose run --rm frontend-build npm install <paket-name>

# Entwicklungs-Abhängigkeit hinzufügen:
docker compose run --rm frontend-build npm install --save-dev <paket-name>

# Dann beide Dateien committen:
git add package.json package-lock.json
git commit -m "Add <paket-name> dependency"
```

#### Abhängigkeiten aktualisieren

```bash
# Alle Abhängigkeiten auf die neuesten Versionen aktualisieren:
docker compose run --rm frontend-build npm update

# Ein bestimmtes Paket aktualisieren:
docker compose run --rm frontend-build npm update <paket-name>

# Dann die Änderungen committen:
git add package-lock.json
git commit -m "Update dependencies"
```

#### Abhängigkeiten lokal installieren

```bash
# Falls Node.js lokal installiert ist:
npm install

# Oder mit Docker:
docker compose run --rm frontend-build npm install
```

#### Entwicklungsserver starten

```bash
# Mit Docker Compose:
docker compose up frontend-build

# Oder lokal:
npm run dev
```

### Warum package-lock.json wichtig ist

Die Datei `package-lock.json` stellt sicher:
- **Reproduzierbare Builds** - Alle verwenden die gleichen Abhängigkeitsversionen
- **Sicherheitsprüfung** - Trivy scannt diese Datei auf Schwachstellen
- **Supply-Chain-Sicherheit** - Fixiert exakte Versionen zur Verhinderung von Angriffen

Committe `package-lock.json` immer in die Versionsverwaltung.
