import { useEffect, useState } from "react";
import type { AxiosError } from "axios";
import { LuPlus, LuRefreshCw } from "react-icons/lu";

import "../screens/advisory-feeds.css";

import {
  createAdvisoryFeed,
  deleteAdvisoryFeed,
  fetchAdvisoryFeeds,
  updateAdvisoryFeed,
  type AdvisoryFeed,
} from "../api/advisoryFeeds";
import { FEED_KINDS, type FeedKind } from "../api/cert";
import { triggerCertFeedsSync } from "../api/sync";
import { useI18n, type TranslateFn } from "../i18n/context";
import { EmptyState, ErrorState, Section } from "../ui/primitives";
import { feedKindLabel } from "../utils/certTopics";
import { ConfirmDialog } from "./ConfirmDialog";
import { SkeletonBlock } from "./Skeleton";
import { useToastContext } from "./ToastProvider";

const feedKindHelp = (kind: FeedKind, t: TranslateFn): string =>
  kind === "vendor"
    ? t(
        "A vendor or security company (Cloudflare, Microsoft, a product's security blog). Counts as its own voice.",
        "Ein Hersteller oder Sicherheitsunternehmen (Cloudflare, Microsoft, der Security-Blog eines Produkts). Zählt als eigene Stimme.",
      )
    : kind === "community"
      ? t(
          "A person or community account, such as Mastodon. Shown next to the topics, never makes a CVE trend on its own and never reads linked pages.",
          "Eine Person oder ein Community-Konto, etwa Mastodon. Erscheint bei den Themen, lässt eine CVE nie allein trenden und liest keine verlinkten Seiten.",
        )
      : t(
          "A national or sector CERT. Two of them naming the same CVE within a week put it under Needs attention.",
          "Ein nationales oder Branchen-CERT. Nennen zwei davon dieselbe CVE innerhalb einer Woche, steht sie unter Handlungsbedarf.",
        );

const errorDetail = (error: unknown, fallback: string): string => {
  const detail = (error as AxiosError<{ detail?: unknown }>).response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
};

interface FormState {
  name: string;
  url: string;
  kind: FeedKind;
}

const EMPTY_FORM: FormState = { name: "", url: "", kind: "cert" };

/**
 * System -> Data: the feeds the advisory sync reads. `.env` feeds are listed
 * read-only; feeds added here go through the same parser, limits and job.
 */
export const AdvisoryFeedsPanel = () => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [feeds, setFeeds] = useState<AdvisoryFeed[]>([]);
  const [syncEnabled, setSyncEnabled] = useState(true);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  // `null` = closed, "" = adding, an id = editing that feed.
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<AdvisoryFeed | null>(null);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    fetchAdvisoryFeeds()
      .then((list) => {
        setFeeds(list.items);
        setSyncEnabled(list.syncEnabled);
        setStatus("ready");
      })
      .catch(() => setStatus("error"));
  }, []);

  const editedFeed = editing ? feeds.find((feed) => feed.id === editing) : undefined;

  const openForm = (feed?: AdvisoryFeed) => {
    setEditing(feed?.id ?? "");
    setForm(feed ? { name: feed.name, url: feed.url, kind: feed.kind } : EMPTY_FORM);
  };

  const closeForm = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
  };

  const replace = (updated: AdvisoryFeed) =>
    setFeeds((current) => current.map((feed) => (feed.id === updated.id ? updated : feed)));

  const handleSave = async () => {
    setSaving(true);
    try {
      if (editedFeed?.id) {
        // The URL comes back with credentials masked, so it is only sent once it was really changed.
        const updated = await updateAdvisoryFeed(editedFeed.id, {
          name: form.name.trim(),
          kind: form.kind,
          ...(form.url.trim() !== editedFeed.url ? { url: form.url.trim() } : {}),
        });
        replace(updated);
        showToast(t(`Feed "${updated.name}" saved.`, `Feed „${updated.name}“ gespeichert.`), "success");
      } else {
        const created = await createAdvisoryFeed({ name: form.name.trim(), url: form.url.trim(), kind: form.kind });
        setFeeds((current) => [...current, created]);
        showToast(
          t(
            `Feed "${created.name}" added. It is read on the next sync.`,
            `Feed „${created.name}“ hinzugefügt. Er wird beim nächsten Sync gelesen.`,
          ),
          "success",
        );
      }
      closeForm();
    } catch (error) {
      showToast(errorDetail(error, t("Failed to save the feed.", "Feed konnte nicht gespeichert werden.")), "error");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (feed: AdvisoryFeed) => {
    if (!feed.id) return;
    setBusyId(feed.id);
    try {
      replace(await updateAdvisoryFeed(feed.id, { enabled: !feed.enabled }));
    } catch (error) {
      showToast(errorDetail(error, t("Failed to save the feed.", "Feed konnte nicht gespeichert werden.")), "error");
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (feed: AdvisoryFeed) => {
    if (!feed.id) return;
    try {
      await deleteAdvisoryFeed(feed.id);
      setFeeds((current) => current.filter((item) => item.id !== feed.id));
      if (editing === feed.id) closeForm();
      showToast(t(`Feed "${feed.name}" removed.`, `Feed „${feed.name}“ entfernt.`), "success");
    } catch (error) {
      showToast(errorDetail(error, t("Failed to remove the feed.", "Feed konnte nicht entfernt werden.")), "error");
    } finally {
      setDeleting(null);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      await triggerCertFeedsSync();
      showToast(t("Reading the feeds now. Sync status shows the result.", "Die Feeds werden jetzt gelesen. Der Sync-Status zeigt das Ergebnis."), "success");
    } catch (error) {
      showToast(errorDetail(error, t("Failed to start the sync.", "Sync konnte nicht gestartet werden.")), "error");
    } finally {
      setSyncing(false);
    }
  };

  const canSave = form.name.trim().length > 0 && form.url.trim().length > 0 && !saving;

  return (
    <Section
      title={t("Advisory feeds", "Meldungs-Feeds")}
      actions={
        <>
          <button type="button" className="btn btn-secondary" onClick={() => void handleSync()} disabled={syncing || !syncEnabled}>
            <LuRefreshCw aria-hidden="true" />
            {t("Read now", "Jetzt lesen")}
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => openForm()} disabled={editing !== null}>
            <LuPlus aria-hidden="true" />
            {t("Add feed", "Feed hinzufügen")}
          </button>
        </>
      }
    >
      <p className="system-section-help">
        {t(
          "RSS, RDF or Atom feeds that the Advisories page and Needs attention read every two hours. Feeds from .env (CERT_FEEDS, CERT_FEEDS_EXTRA) are listed here but changed only there.",
          "RSS-, RDF- oder Atom-Feeds, die die Seite Meldungen und Handlungsbedarf alle zwei Stunden lesen. Feeds aus der .env (CERT_FEEDS, CERT_FEEDS_EXTRA) stehen hier mit, werden aber nur dort geändert.",
        )}
      </p>

      {!syncEnabled && (
        <p className="advisory-feeds-note" role="status">
          {t(
            "CERT_FEEDS_ENABLED is false, so no feed is read, including the ones added here.",
            "CERT_FEEDS_ENABLED ist false, deshalb wird kein Feed gelesen, auch keiner der hier hinzugefügten.",
          )}
        </p>
      )}

      {editing !== null && (
        <form
          className="well system-form advisory-feeds-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (canSave) void handleSave();
          }}
        >
          <label className="advisory-feeds-field">
            <span>{t("Name", "Name")}</span>
            <input
              className="system-input"
              value={form.name}
              maxLength={64}
              onChange={(event) => setForm({ ...form, name: event.target.value })}
              placeholder={t("e.g. Cloudflare or @user@infosec.exchange", "z. B. Cloudflare oder @user@infosec.exchange")}
            />
          </label>
          <label className="advisory-feeds-field advisory-feeds-field--url">
            <span>URL</span>
            <input
              className="system-input mono"
              value={form.url}
              maxLength={2048}
              inputMode="url"
              onChange={(event) => setForm({ ...form, url: event.target.value })}
              placeholder="https://infosec.exchange/@user.rss"
            />
          </label>
          <fieldset className="advisory-feeds-kinds">
            <legend>{t("Kind", "Art")}</legend>
            {FEED_KINDS.map((kind) => (
              <label key={kind} className="advisory-feeds-kind">
                <input
                  type="radio"
                  name="advisory-feed-kind"
                  checked={form.kind === kind}
                  onChange={() => setForm({ ...form, kind })}
                />
                <span>
                  <strong>{feedKindLabel(kind, t)}</strong>
                  <span className="advisory-feeds-kind-help">{feedKindHelp(kind, t)}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <p className="advisory-feeds-hint">
            {t(
              "A Mastodon account has its feed at https://<instance>/@<user>.rss. Only public addresses are accepted unless CERT_FEEDS_ALLOW_PRIVATE_HOSTS is set.",
              "Ein Mastodon-Konto hat seinen Feed unter https://<instanz>/@<nutzer>.rss. Nur öffentliche Adressen werden angenommen, außer CERT_FEEDS_ALLOW_PRIVATE_HOSTS ist gesetzt.",
            )}
          </p>
          <div className="advisory-feeds-actions">
            <button type="submit" className="btn btn-primary" disabled={!canSave}>
              {saving ? t("Saving...", "Speichern…") : editedFeed ? t("Save", "Speichern") : t("Add feed", "Feed hinzufügen")}
            </button>
            <button type="button" className="btn btn-secondary" onClick={closeForm}>
              {t("Cancel", "Abbrechen")}
            </button>
          </div>
        </form>
      )}

      {status === "loading" ? (
        <div className="system-skeleton" role="status">
          {[0, 1, 2].map((index) => (
            <SkeletonBlock key={index} height={36} />
          ))}
        </div>
      ) : status === "error" ? (
        <ErrorState title={t("Advisory feeds could not be loaded.", "Meldungs-Feeds konnten nicht geladen werden.")} />
      ) : feeds.length === 0 ? (
        <EmptyState title={t("No advisory feeds configured.", "Keine Meldungs-Feeds konfiguriert.")} />
      ) : (
        <div className="table-scroll">
          <table className="system-table advisory-feeds-table">
            <thead>
              <tr>
                <th scope="col">{t("Name", "Name")}</th>
                <th scope="col">{t("Kind", "Art")}</th>
                <th scope="col">URL</th>
                <th scope="col">{t("Source", "Quelle")}</th>
                <th scope="col" className="system-cell-action">{t("Actions", "Aktionen")}</th>
              </tr>
            </thead>
            <tbody>
              {feeds.map((feed) => (
                <tr key={feed.id ?? `env:${feed.name}`} className={feed.enabled ? undefined : "advisory-feeds-off"}>
                  <td className="system-cell-name">{feed.name}</td>
                  <td data-label={t("Kind", "Art")}>
                    <span className={`chip advisory-kind advisory-kind--${feed.kind}`}>{feedKindLabel(feed.kind, t)}</span>
                  </td>
                  <td data-label="URL" className="advisory-feeds-url">
                    <code className="system-code">{feed.url}</code>
                  </td>
                  <td data-label={t("Source", "Quelle")}>
                    {feed.origin === "env" ? (
                      <span className="mono">.env</span>
                    ) : (
                      <button
                        type="button"
                        className={`system-toggle${feed.enabled ? "" : " system-toggle--off"}`}
                        aria-pressed={feed.enabled}
                        disabled={busyId === feed.id}
                        onClick={() => void handleToggle(feed)}
                        title={t("Click to switch on or off", "Klicken zum Ein- oder Ausschalten")}
                      >
                        {feed.enabled ? t("UI · on", "UI · an") : t("UI · off", "UI · aus")}
                      </button>
                    )}
                  </td>
                  <td className="system-cell-action">
                    {feed.origin === "ui" && (
                      <span className="system-row-actions">
                        <button type="button" className="btn btn-secondary" onClick={() => openForm(feed)} disabled={editing !== null}>
                          {t("Edit", "Bearbeiten")}
                        </button>
                        <button type="button" className="btn btn-secondary system-btn-danger" onClick={() => setDeleting(feed)}>
                          {t("Remove", "Entfernen")}
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {deleting && (
        <ConfirmDialog
          title={t(`Remove "${deleting.name}"?`, `„${deleting.name}“ entfernen?`)}
          message={t(
            "The feed is no longer read. What it already delivered stays on the Advisories page until it leaves the time window.",
            "Der Feed wird nicht mehr gelesen. Was er schon geliefert hat, bleibt auf der Seite Meldungen, bis es aus dem Zeitraum fällt.",
          )}
          confirmLabel={t("Remove", "Entfernen")}
          onConfirm={() => handleDelete(deleting)}
          onCancel={() => setDeleting(null)}
        />
      )}
    </Section>
  );
};
