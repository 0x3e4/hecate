import { Fragment, useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { LuChevronRight, LuPlus } from "react-icons/lu";
import { useNavigate } from "react-router-dom";

import "../screens/system.css";

import {
  exportInventoryBackup,
  exportSavedSearchesBackup,
  exportVulnerabilityBackup,
  restoreInventoryBackup,
  restoreSavedSearchesBackup,
  restoreVulnerabilityBackup,
  type VulnerabilitySource
} from "../api/backup";
import {
  fetchNotificationStatus,
  sendTestNotification,
  fetchNotificationRules,
  createNotificationRule,
  updateNotificationRule,
  deleteNotificationRule,
  fetchNotificationChannels,
  addNotificationChannel,
  removeNotificationChannel,
  fetchNotificationTemplates,
  createNotificationTemplate,
  updateNotificationTemplate,
  deleteNotificationTemplate,
} from "../api/notifications";
import { api } from "../api/client";
import {
  fetchLicensePolicies,
  createLicensePolicy,
  updateLicensePolicy,
  deleteLicensePolicy,
  setDefaultLicensePolicy,
  fetchLicenseGroups,
} from "../api/licensePolicy";
import {
  fetchSyncStates,
  triggerEuvdSync,
  triggerNvdSync,
  triggerCpeSync,
  triggerKevSync,
  triggerCweSync,
  triggerCapecSync,
  triggerCirclSync,
  triggerGhsaSync,
  triggerOsvSync,
  resyncVulnerabilities,
} from "../api/sync";
import { fetchScanTargets } from "../api/scans";
import { setAdminPassword } from "../api/writeAuth";
import { SkeletonBlock } from "../components/Skeleton";
import { ApiTokenPanel } from "../components/ApiTokenPanel";
import { TargetAccessPanel } from "../components/TargetAccessPanel";
import { useToastContext } from "../components/ToastProvider";
import { fetchInventoryItems } from "../api/inventory";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useSSE } from "../hooks/useSSE";
import { useI18n, type TranslateFn } from "../i18n/context";
import type { AppLanguage } from "../i18n/language";
import { useTimezone } from "../timezone/context";
import { listSupportedTimezones } from "../timezone/storage";
import { useServerConfig } from "../server-config/context";
import { EmptyState, PageHeader, Section } from "../ui/primitives";
import { tabPillStyle } from "../ui/TabPill";
import type {
  NotificationChannel,
  NotificationEventKey,
  NotificationStatusResponse,
  NotificationRule,
  NotificationRuleCreate,
  NotificationRuleType,
  NotificationTemplate,
  NotificationTemplateCreate,
  SavedSearch,
  SyncState,
  LicensePolicy,
  LicenseGroups,
  ScanTarget,
  InventoryItem,
} from "../types";
import { formatDateTime } from "../utils/dateFormat";

type StatusTone = "ok" | "error" | "info" | "muted";

/** One setting: label and one-line help on the left, the control on the right. */
const Setting = ({
  label,
  help,
  htmlFor,
  children,
}: {
  label: ReactNode;
  help?: ReactNode;
  htmlFor?: string;
  children: ReactNode;
}) => (
  <div className="system-setting">
    <div className="system-setting-text">
      {htmlFor ? (
        <label className="system-setting-label" htmlFor={htmlFor}>{label}</label>
      ) : (
        <span className="system-setting-label">{label}</span>
      )}
      {help ? <p className="system-setting-help">{help}</p> : null}
    </div>
    <div
      className="system-setting-control"
      role={htmlFor ? undefined : "group"}
      aria-label={!htmlFor && typeof label === "string" ? label : undefined}
    >
      {children}
    </div>
  </div>
);

/** A state as a word, never colour alone. */
const StatusWord = ({ tone, children }: { tone: StatusTone; children: ReactNode }) => (
  <span className={`system-status system-status--${tone}`}>{children}</span>
);

/** Loading placeholder shaped like the rows it stands in for. */
const RowsSkeleton = ({ rows, label }: { rows: number; label: string }) => (
  <div className="system-skeleton" role="status">
    <span className="visually-hidden">{label}</span>
    {Array.from({ length: rows }, (_, index) => (
      <SkeletonBlock key={index} height={36} />
    ))}
  </div>
);

type SystemTab = "general" | "access" | "notifications" | "data" | "policies";

type BackupDataset =
  | { id: "VULNERABILITIES"; label: string; description: string; type: "vuln"; source: VulnerabilitySource }
  | { id: "SAVED_SEARCHES"; label: string; description: string; type: "saved_searches" }
  | { id: "INVENTORY"; label: string; description: string; type: "inventory" }

const createBackupDatasets = (t: TranslateFn): BackupDataset[] => [
  {
    id: "VULNERABILITIES",
    label: t("Vulnerabilities", "Schwachstellen"),
    description: t(
      "Backup of all vulnerability entries (NVD & EUVD)",
      "Sicherung aller Vulnerability-Einträge (NVD & EUVD)"
    ),
    type: "vuln",
    source: "ALL"
  },
  {
    id: "SAVED_SEARCHES",
    label: t("Saved searches", "Gespeicherte Suchen"),
    description: t("Backup of all saved search filters", "Sicherung aller gespeicherten Suchfilter"),
    type: "saved_searches"
  },
  {
    id: "INVENTORY",
    label: t("Environment Inventory", "Umgebungs-Inventar"),
    description: t(
      "Backup of all declared inventory items (products, versions, deployment metadata)",
      "Sicherung aller deklarierten Inventar-Einträge (Produkte, Versionen, Deployment-Metadaten)"
    ),
    type: "inventory"
  }
];

export const SystemPage = () => {
  const { language, locale, setLanguage, t } = useI18n();
  const { timezone, isBrowserDefault, setTimezone } = useTimezone();
  const supportedTimezones = useMemo(() => listSupportedTimezones(), []);
  const [timezoneDraft, setTimezoneDraft] = useState<string>(isBrowserDefault ? "" : timezone);
  useEffect(() => {
    setTimezoneDraft(isBrowserDefault ? "" : timezone);
  }, [timezone, isBrowserDefault]);
  const { aiBatchMaxVulns } = useServerConfig();
  const [aiBatchDraft, setAiBatchDraft] = useState<string>(String(aiBatchMaxVulns));
  const [aiBatchSaving, setAiBatchSaving] = useState(false);
  const navigate = useNavigate();

  // --- System password gate ---
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authOk, setAuthOk] = useState(false);
  const [authPassword, setAuthPassword] = useState("");
  const [authChecking, setAuthChecking] = useState(false);
  const [tab, setTab] = useState<SystemTab>("general");

  useEffect(() => {
    api.get<{ required: boolean }>("/v1/status/system-auth").then((r) => {
      setAuthRequired(r.data.required);
      if (!r.data.required) setAuthOk(true);
    }).catch(() => {
      setAuthRequired(false);
      setAuthOk(true);
    });
  }, []);

  const handleAuthSubmit = async () => {
    setAuthChecking(true);
    try {
      const r = await api.post<{ authenticated: boolean }>("/v1/status/system-auth", { password: authPassword });
      if (r.data.authenticated) {
        setAuthOk(true);
        // Persist so the axios interceptor can attach X-System-Password to write
        // requests from any page (delete target, manage notifications, etc.).
        setAdminPassword(authPassword);
      }
    } catch {
      showToast(t("Invalid password.", "Falsches Passwort."), "error");
    } finally {
      setAuthChecking(false);
    }
  };

  // --- Regular state ---
  const [busyId, setBusyId] = useState<string | null>(null);
  const { showToast } = useToastContext();

  const handleSaveAiBatchLimit = async () => {
    const value = Number(aiBatchDraft);
    if (!Number.isInteger(value) || value < 1 || value > 100) {
      showToast(t("Enter a whole number between 1 and 100.", "Gib eine ganze Zahl zwischen 1 und 100 ein."), "error");
      return;
    }
    setAiBatchSaving(true);
    try {
      const res = await api.put<{ aiBatchMaxVulns: number }>("/v1/app-settings", { aiBatchMaxVulns: value });
      setAiBatchDraft(String(res.data.aiBatchMaxVulns));
      showToast(t("Batch limit saved.", "Batch-Limit gespeichert."), "success");
    } catch {
      showToast(t("Could not save batch limit.", "Batch-Limit konnte nicht gespeichert werden."), "error");
    } finally {
      setAiBatchSaving(false);
    }
  };
  const [deletePendingId, setDeletePendingId] = useState<string | null>(null);
  const fileInputs = useRef<Record<string, HTMLInputElement | null>>({});
  const { savedSearches, loading: savedSearchLoading, updateSavedSearch, removeSavedSearch, refresh: refreshSavedSearches } = useSavedSearches();
  const [editingSearchId, setEditingSearchId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDqlQuery, setEditDqlQuery] = useState("");
  const [editQueryParams, setEditQueryParams] = useState("");
  const [editSaving, setEditSaving] = useState(false);

  const [syncStates, setSyncStates] = useState<SyncState[]>([]);
  const [syncLoading, setSyncLoading] = useState(true);
  const [syncTriggeringId, setSyncTriggeringId] = useState<string | null>(null);
  const [expandedSyncId, setExpandedSyncId] = useState<string | null>(null);
  const syncIntervalRef = useRef<number | null>(null);

  const [resyncInput, setResyncInput] = useState("");
  const [resyncBusy, setResyncBusy] = useState(false);

  // License policies
  const [licensePolicies, setLicensePolicies] = useState<LicensePolicy[]>([]);
  const [licensePoliciesLoading, setLicensePoliciesLoading] = useState(true);
  const [licenseGroups, setLicenseGroups] = useState<LicenseGroups | null>(null);
  const [lpEditing, setLpEditing] = useState<LicensePolicy | null>(null);
  const [lpCreating, setLpCreating] = useState(false);
  const [lpFormName, setLpFormName] = useState("");
  const [lpFormDescription, setLpFormDescription] = useState("");
  const [lpFormAllowed, setLpFormAllowed] = useState("");
  const [lpFormDenied, setLpFormDenied] = useState("");
  const [lpFormDefaultAction, setLpFormDefaultAction] = useState("warn");
  const [lpFormIsDefault, setLpFormIsDefault] = useState(false);

  // SSE for real-time job updates
  const { jobs: sseJobs, connected: sseConnected } = useSSE();
  const backupDatasets = useMemo<BackupDataset[]>(() => createBackupDatasets(t), [t]);

  const [notifStatus, setNotifStatus] = useState<NotificationStatusResponse | null>(null);
  const [notifLoading, setNotifLoading] = useState(true);
  const [notifTestBusy, setNotifTestBusy] = useState(false);
  const [notifTestTag, setNotifTestTag] = useState("");

  const [scannerStatus, setScannerStatus] = useState<{ enabled: boolean; reachable: boolean } | null>(null);
  const [scannerLoading, setScannerLoading] = useState(true);

  const [notifRules, setNotifRules] = useState<NotificationRule[]>([]);
  const [notifRulesLoading, setNotifRulesLoading] = useState(true);
  const [ruleDeletePendingId, setRuleDeletePendingId] = useState<string | null>(null);
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [editingRule, setEditingRule] = useState<NotificationRule | null>(null);
  const [ruleSaving, setRuleSaving] = useState(false);

  // Rule form state
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState<NotificationRuleType>("event");
  const [formTag, setFormTag] = useState("all");
  const [formEnabled, setFormEnabled] = useState(true);
  const [formEventTypes, setFormEventTypes] = useState<string[]>([]);
  const [formSavedSearchId, setFormSavedSearchId] = useState("");
  const [formVendorSlug, setFormVendorSlug] = useState("");
  const [formProductSlug, setFormProductSlug] = useState("");
  const [formDqlQuery, setFormDqlQuery] = useState("");
  const [formScanSeverityThreshold, setFormScanSeverityThreshold] = useState("");
  const [formScanTargetFilter, setFormScanTargetFilter] = useState("");
  const [formInventoryItemIds, setFormInventoryItemIds] = useState<string[]>([]);
  const [scanTargets, setScanTargets] = useState<ScanTarget[]>([]);
  const [inventoryItems, setInventoryItems] = useState<InventoryItem[]>([]);

  // Channel management state
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [channelsLoading, setChannelsLoading] = useState(true);
  const [showChannelForm, setShowChannelForm] = useState(false);
  const [channelUrl, setChannelUrl] = useState("");
  const [channelTag, setChannelTag] = useState("all");
  const [channelSaving, setChannelSaving] = useState(false);
  const [channelRemovingId, setChannelRemovingId] = useState<string | null>(null);

  // Message template state
  const [templates, setTemplates] = useState<NotificationTemplate[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [showTemplateForm, setShowTemplateForm] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<NotificationTemplate | null>(null);
  const [templateSaving, setTemplateSaving] = useState(false);
  const [templateDeletePendingId, setTemplateDeletePendingId] = useState<string | null>(null);
  const [tplEventKey, setTplEventKey] = useState<NotificationEventKey>("new_vulnerabilities");
  const [tplTag, setTplTag] = useState("all");
  const [tplTitle, setTplTitle] = useState("");
  const [tplBody, setTplBody] = useState("");

  const loadChannels = async () => {
    try {
      const response = await fetchNotificationChannels();
      setChannels(response.items);
    } catch (error) {
      console.error("Failed to load channels", error);
    } finally {
      setChannelsLoading(false);
    }
  };

  const handleAddChannel = async () => {
    if (!channelUrl.trim()) return;
    setChannelSaving(true);
    try {
      await addNotificationChannel(channelUrl.trim(), channelTag.trim() || "all");
      showToast(t("Channel added.", "Kanal hinzugefügt."), "success");
      setChannelUrl("");
      setChannelTag("all");
      setShowChannelForm(false);
      void loadChannels();
    } catch (error) {
      console.error("Add channel failed", error);
      showToast(t("Could not add channel.", "Kanal konnte nicht hinzugefügt werden."), "error");
    } finally {
      setChannelSaving(false);
    }
  };

  const handleRemoveChannel = async (channelId: string) => {
    setChannelRemovingId(channelId);
    try {
      await removeNotificationChannel(channelId);
      showToast(t("Channel removed.", "Kanal entfernt."), "success");
      void loadChannels();
    } catch (error) {
      console.error("Remove channel failed", error);
      showToast(t("Could not remove channel.", "Kanal konnte nicht entfernt werden."), "error");
    } finally {
      setChannelRemovingId(null);
    }
  };

  const loadNotifRules = async () => {
    try {
      const response = await fetchNotificationRules();
      setNotifRules(response.items);
    } catch (error) {
      console.error("Failed to load notification rules", error);
    } finally {
      setNotifRulesLoading(false);
    }
  };

  const resetRuleForm = () => {
    setFormName("");
    setFormType("event");
    setFormTag("all");
    setFormEnabled(true);
    setFormEventTypes([]);
    setFormSavedSearchId("");
    setFormVendorSlug("");
    setFormProductSlug("");
    setFormDqlQuery("");
    setFormScanSeverityThreshold("");
    setFormScanTargetFilter("");
    setFormInventoryItemIds([]);
    setEditingRule(null);
  };

  const openRuleForm = (rule?: NotificationRule) => {
    if (rule) {
      setEditingRule(rule);
      setFormName(rule.name);
      setFormType(rule.ruleType);
      setFormTag(rule.appriseTag);
      setFormEnabled(rule.enabled);
      setFormEventTypes(rule.eventTypes || []);
      setFormSavedSearchId(rule.savedSearchId || "");
      setFormVendorSlug(rule.vendorSlug || "");
      setFormProductSlug(rule.productSlug || "");
      setFormDqlQuery(rule.dqlQuery || "");
      setFormScanSeverityThreshold(rule.scanSeverityThreshold || "");
      setFormScanTargetFilter(rule.scanTargetFilter || "");
      setFormInventoryItemIds(rule.inventoryItemIds || []);
    } else {
      resetRuleForm();
    }
    setShowRuleForm(true);
  };

  const handleSaveRule = async () => {
    if (!formName.trim()) return;
    setRuleSaving(true);
    try {
      const payload: NotificationRuleCreate = {
        name: formName.trim(),
        enabled: formEnabled,
        ruleType: formType,
        appriseTag: formTag.trim() || "all",
        eventTypes: formType === "event" ? formEventTypes : [],
        savedSearchId: formType === "saved_search" ? formSavedSearchId || null : null,
        vendorSlug: formType === "vendor" ? formVendorSlug || null : null,
        productSlug: formType === "product" ? formProductSlug || null : null,
        dqlQuery: formType === "dql" ? formDqlQuery || null : null,
        scanSeverityThreshold:
          formType === "scan" || formType === "sca_malware_alert"
            ? formScanSeverityThreshold || null
            : null,
        scanTargetFilter:
          formType === "scan" || formType === "sca_malware_alert"
            ? formScanTargetFilter || null
            : null,
        inventoryItemIds: formType === "inventory" ? (formInventoryItemIds.length ? formInventoryItemIds : null) : null,
      };
      if (editingRule) {
        await updateNotificationRule(editingRule.id, payload);
        showToast(t(`Rule "${formName}" updated.`, `Regel "${formName}" aktualisiert.`), "success");
      } else {
        await createNotificationRule(payload);
        showToast(t(`Rule "${formName}" created.`, `Regel "${formName}" erstellt.`), "success");
      }
      setShowRuleForm(false);
      resetRuleForm();
      void loadNotifRules();
    } catch (error) {
      console.error("Save rule failed", error);
      showToast(t("Could not save rule.", "Regel konnte nicht gespeichert werden."), "error");
    } finally {
      setRuleSaving(false);
    }
  };

  const handleDeleteRule = async (rule: NotificationRule) => {
    setRuleDeletePendingId(rule.id);
    try {
      await deleteNotificationRule(rule.id);
      showToast(t(`Rule "${rule.name}" deleted.`, `Regel "${rule.name}" gelöscht.`), "success");
      void loadNotifRules();
    } catch (error) {
      console.error("Delete rule failed", error);
      showToast(t("Could not delete rule.", "Regel konnte nicht gelöscht werden."), "error");
    } finally {
      setRuleDeletePendingId(null);
    }
  };

  const handleToggleRule = async (rule: NotificationRule) => {
    try {
      await updateNotificationRule(rule.id, {
        name: rule.name,
        enabled: !rule.enabled,
        ruleType: rule.ruleType,
        appriseTag: rule.appriseTag,
        eventTypes: rule.eventTypes,
        savedSearchId: rule.savedSearchId,
        vendorSlug: rule.vendorSlug,
        productSlug: rule.productSlug,
        dqlQuery: rule.dqlQuery,
        scanSeverityThreshold: rule.scanSeverityThreshold,
        scanTargetFilter: rule.scanTargetFilter,
      });
      void loadNotifRules();
    } catch (error) {
      console.error("Toggle rule failed", error);
    }
  };

  const toggleEventType = (eventType: string) => {
    setFormEventTypes((prev) =>
      prev.includes(eventType) ? prev.filter((e) => e !== eventType) : [...prev, eventType]
    );
  };

  const getRuleTypeLabel = (type: NotificationRuleType): string => {
    switch (type) {
      case "event": return t("System Event", "System-Ereignis");
      case "saved_search": return t("Saved Search", "Gespeicherte Suche");
      case "vendor": return t("Vendor", "Hersteller");
      case "product": return t("Product", "Produkt");
      case "dql": return t("DQL Query", "DQL-Abfrage");
      case "scan": return t("SCA Scan", "SCA-Scan");
      case "inventory": return t("Inventory", "Inventar");
      case "sca_malware_alert": return t("SCA Malware Alert", "SCA-Malware-Alarm");
    }
  };

  const getRuleDescription = (rule: NotificationRule): string => {
    switch (rule.ruleType) {
      case "event": return rule.eventTypes.join(", ") || "n/a";
      case "saved_search": {
        const search = sortedSavedSearches.find((s) => s.id === rule.savedSearchId);
        if (!search) {
          return `${t("Missing saved search", "Gespeicherte Suche fehlt")}: ${rule.savedSearchId || "(no id)"}`;
        }
        return search.name;
      }
      case "vendor": return rule.vendorSlug || "n/a";
      case "product": return rule.productSlug || "n/a";
      case "dql": return rule.dqlQuery?.substring(0, 60) || "n/a";
      case "scan": {
        const parts: string[] = [];
        if (rule.scanSeverityThreshold) parts.push(`>= ${rule.scanSeverityThreshold}`);
        if (rule.scanTargetFilter) parts.push(rule.scanTargetFilter);
        return parts.join(", ") || t("All scans", "Alle Scans");
      }
      case "sca_malware_alert": {
        const parts: string[] = [];
        if (rule.scanSeverityThreshold) parts.push(`>= ${rule.scanSeverityThreshold}`);
        if (rule.scanTargetFilter) parts.push(rule.scanTargetFilter);
        return parts.join(", ") || t("All targets", "Alle Ziele");
      }
      case "inventory": {
        const ids = rule.inventoryItemIds || [];
        if (ids.length === 0) return t("All inventory items", "Alle Inventar-Einträge");
        return t(`${ids.length} item(s)`, `${ids.length} Eintrag/Einträge`);
      }
    }
  };

  // --- Message Template Handlers ---

  const EVENT_KEY_OPTIONS: { value: NotificationEventKey; label: string }[] = [
    { value: "new_vulnerabilities", label: "New Vulnerabilities" },
    { value: "scan_completed", label: "Scan Completed" },
    { value: "scan_failed", label: "Scan Failed" },
    { value: "sync_failed", label: "Sync Failed" },
    { value: "watch_rule_match", label: "Watch Rule Match" },
    { value: "inventory_match", label: "Inventory Match" },
    { value: "sca_malware_alert", label: "SCA Malware Alert" },
  ];

  const TEMPLATE_PLACEHOLDERS: Record<NotificationEventKey, { scalars: string; loops?: { label: string; fields: string }[] }> = {
    new_vulnerabilities: { scalars: "{icon}, {source}, {count}, {noun}, {time}" },
    scan_completed: {
      scalars: "{icon}, {target}, {target_type}, {status}, {findings}, {duration}, {scan_id}, {time}, {critical}, {high}, {medium}, {low}, {negligible}, {unknown}, {alerts}, {alerts_critical}, {alerts_high}, {alerts_medium}, {alerts_low}, {sast}, {sast_critical}, {sast_high}, {sast_medium}, {sast_low}, {secrets}, {secrets_verified}, {secrets_unverified}, {compliance}, {compliance_critical}, {compliance_high}, {compliance_medium}, {compliance_low}, {licenses}, {licenses_allowed}, {licenses_denied}, {licenses_warned}, {licenses_unknown}, {scanners}, {source}, {branch}, {commit_sha}, {image_ref}, {sbom_components}",
      loops: [
        { label: "findings_list", fields: "{id}, {severity}, {cvss}, {package}, {version}, {fix}, {title}" },
        { label: "alerts_list", fields: "{severity}, {package}, {title}" },
        { label: "sast_list", fields: "{severity}, {title}, {file}" },
        { label: "secrets_list", fields: "{severity}, {detector}, {file}, {verified}" },
      ],
    },
    scan_failed: {
      scalars: "{icon}, {target}, {target_type}, {status}, {findings}, {duration}, {scan_id}, {time}, {critical}, {high}, {medium}, {low}, {error}, {alerts}, {sast}, {secrets}, {compliance}, {scanners}, {source}, {branch}, {commit_sha}, {image_ref}",
      loops: [
        { label: "findings_list", fields: "{id}, {severity}, {cvss}, {package}, {version}, {fix}, {title}" },
      ],
    },
    sync_failed: { scalars: "{job_name}, {error}, {time}" },
    watch_rule_match: {
      scalars: "{icon}, {rule_name}, {count}, {noun}, {vulnerabilities_list}, {vendors}, {products}, {versions}, {time}",
      loops: [
        { label: "vulnerabilities", fields: "{id}, {severity}, {cvss}, {cwes}, {summary}, {title}, {vendors}, {products}, {versions}, {exploited}, {source}, {published}" },
      ],
    },
    inventory_match: {
      scalars: "{icon}, {rule_name}, {count}, {noun}, {vulnerabilities_list}, {affected_item_count}, {total_instances}, {time}",
      loops: [
        { label: "vulnerabilities", fields: "{id}, {severity}, {cvss}, {title}, {published}, {affectedItems}" },
        { label: "affected_items", fields: "{id}, {name}, {version}, {deployment}, {environment}, {instanceCount}, {owner}" },
      ],
    },
    sca_malware_alert: {
      scalars: "{icon}, {target}, {scan_id}, {mal_count}, {noun}, {packages_list}, {time}",
      loops: [
        { label: "malware", fields: "{mal_id}, {package}, {version}, {ecosystem}, {severity}, {title}" },
      ],
    },
  };

  const DEFAULT_TEMPLATES: Record<NotificationEventKey, { title: string; body: string }> = {
    new_vulnerabilities: {
      title: "{icon} Hecate — {count} New {noun}",
      body: "Source: {source}\nNew entries: {count}\nTime: {time}",
    },
    scan_completed: {
      title: "{icon} Hecate — SCA Scan {status}",
      body: "Target: {target}\nVulnerabilities: {findings} (C:{critical} H:{high} M:{medium} L:{low})\nAlerts: {alerts} | SAST: {sast} | Secrets: {secrets} | Compliance: {compliance}\nSBOM: {sbom_components} components | Licenses: {licenses}\nScanners: {scanners}\nDuration: {duration}s",
    },
    scan_failed: {
      title: "{icon} Hecate — SCA Scan {status}",
      body: "Target: {target}\nError: {error}\nVulnerabilities: {findings} (C:{critical} H:{high} M:{medium} L:{low})\nAlerts: {alerts} | SAST: {sast} | Secrets: {secrets}\nScanners: {scanners}\nDuration: {duration}s",
    },
    sync_failed: {
      title: "Hecate — Sync Failed: {job_name}",
      body: "Job: {job_name}\nError: {error}\nTime: {time}",
    },
    watch_rule_match: {
      title: "{icon} Hecate — {count} New {noun}: {rule_name}",
      body: "Rule: {rule_name}\nMatches: {count}\nVulnerabilities: {vulnerabilities_list}\nTime: {time}",
    },
    inventory_match: {
      title: "{icon} Hecate — {count} inventory-affecting {noun}: {rule_name}",
      body: "Rule: {rule_name}\nNew vulnerabilities affecting your inventory: {count}\nInventory items impacted: {affected_item_count} ({total_instances} instances)\nVulnerabilities: {vulnerabilities_list}\nTime: {time}",
    },
    sca_malware_alert: {
      title: "{icon} Hecate — {mal_count} new MAL-* {noun} on {target}",
      body: "Target: {target}\nScan: {scan_id}\nNew MAL-* findings: {mal_count}\nPackages: {packages_list}\nTime: {time}",
    },
  };

  const loadTemplates = async () => {
    try {
      const response = await fetchNotificationTemplates();
      setTemplates(response.items);
    } catch (error) {
      console.error("Failed to load templates", error);
    } finally {
      setTemplatesLoading(false);
    }
  };

  const resetTemplateForm = () => {
    const def = DEFAULT_TEMPLATES["new_vulnerabilities"];
    setTplEventKey("new_vulnerabilities");
    setTplTag("all");
    setTplTitle(def.title);
    setTplBody(def.body);
    setEditingTemplate(null);
  };

  const openTemplateForm = (tpl?: NotificationTemplate) => {
    if (tpl) {
      setEditingTemplate(tpl);
      setTplEventKey(tpl.eventKey);
      setTplTag(tpl.tag);
      setTplTitle(tpl.titleTemplate);
      setTplBody(tpl.bodyTemplate);
    } else {
      resetTemplateForm();
    }
    setShowTemplateForm(true);
  };

  const handleSaveTemplate = async () => {
    if (!tplTitle.trim() || !tplBody.trim()) return;
    setTemplateSaving(true);
    try {
      const payload: NotificationTemplateCreate = {
        eventKey: tplEventKey,
        tag: tplTag.trim() || "all",
        titleTemplate: tplTitle.trim(),
        bodyTemplate: tplBody.trim(),
      };
      if (editingTemplate) {
        await updateNotificationTemplate(editingTemplate.id, payload);
        showToast(t("Template updated.", "Vorlage aktualisiert."), "success");
      } else {
        await createNotificationTemplate(payload);
        showToast(t("Template created.", "Vorlage erstellt."), "success");
      }
      setShowTemplateForm(false);
      resetTemplateForm();
      void loadTemplates();
    } catch (error) {
      console.error("Save template failed", error);
      showToast(t("Could not save template.", "Vorlage konnte nicht gespeichert werden."), "error");
    } finally {
      setTemplateSaving(false);
    }
  };

  const handleDeleteTemplate = async (tpl: NotificationTemplate) => {
    setTemplateDeletePendingId(tpl.id);
    try {
      await deleteNotificationTemplate(tpl.id);
      showToast(t("Template deleted.", "Vorlage gelöscht."), "success");
      void loadTemplates();
    } catch (error) {
      console.error("Delete template failed", error);
      showToast(t("Could not delete template.", "Vorlage konnte nicht gelöscht werden."), "error");
    } finally {
      setTemplateDeletePendingId(null);
    }
  };

  const getEventKeyLabel = (key: NotificationEventKey): string => {
    const opt = EVENT_KEY_OPTIONS.find((o) => o.value === key);
    return opt ? opt.label : key;
  };

  const handleExport = async (dataset: BackupDataset) => {
    setBusyId(dataset.id);
    try {
      const response =
        dataset.type === "vuln"
          ? await exportVulnerabilityBackup(dataset.source)
          : dataset.type === "inventory"
            ? await exportInventoryBackup()
            : await exportSavedSearchesBackup();

      const timestamp = new Date().toISOString().replace(/[:]/g, "").replace(/\..+/, "");
      const fallbackName =
        dataset.type === "vuln"
          ? `${dataset.source.toLowerCase()}-backup-${timestamp}.json`
          : dataset.type === "inventory"
            ? `inventory-backup-${timestamp}.json`
            : `saved-searches-backup-${timestamp}.json`;
      const filename = response.filename ?? fallbackName;

      const url = URL.createObjectURL(response.data);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);

      showToast(
        t(
          `${dataset.label}: Backup is ready (${filename}).`,
          `${dataset.label}: Sicherung bereitgestellt (${filename}).`
        ),
        "success"
      );
    } catch (error) {
      console.error("Backup export failed", error);
      showToast(
        t(
          `Could not create backup for ${dataset.label}.`,
          `Backup für ${dataset.label} konnte nicht erstellt werden.`
        ),
        "error"
      );
    } finally {
      setBusyId(null);
    }
  };

  const sortedSavedSearches = useMemo<SavedSearch[]>(
    () => [...savedSearches].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" })),
    [savedSearches]
  );

  const loadScannerStatus = async () => {
    try {
      const response = await api.get<{ enabled: boolean; reachable: boolean }>("/v1/status/scanner-health");
      setScannerStatus(response.data);
    } catch (error) {
      console.error("Failed to load scanner status", error);
    } finally {
      setScannerLoading(false);
    }
  };

  const loadNotificationStatus = async () => {
    try {
      const status = await fetchNotificationStatus();
      setNotifStatus(status);
    } catch (error) {
      console.error("Failed to load notification status", error);
    } finally {
      setNotifLoading(false);
    }
  };

  const handleTestNotification = async () => {
    setNotifTestBusy(true);
    try {
      const result = await sendTestNotification(notifTestTag.trim() || undefined);
      showToast(result.message, result.success ? "success" : "error");
    } catch (error) {
      console.error("Test notification failed", error);
      showToast(t("Could not send test notification.", "Testbenachrichtigung konnte nicht gesendet werden."), "error");
    } finally {
      setNotifTestBusy(false);
    }
  };

  const loadSyncStates = async () => {
    try {
      const response = await fetchSyncStates();
      setSyncStates(response.syncs);
      setSyncLoading(false);
    } catch (error) {
      console.error("Failed to load sync states", error);
      setSyncLoading(false);
    }
  };

  useEffect(() => {
    document.title = `${t("Hecate Cyber Defense - System", "Hecate Cyber Defense - System")}`;

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

  const loadLicensePolicies = async () => {
    try {
      const [policiesRes, groupsRes] = await Promise.all([
        fetchLicensePolicies(),
        fetchLicenseGroups(),
      ]);
      setLicensePolicies(policiesRes.items);
      setLicenseGroups(groupsRes);
    } catch (error) {
      console.error("Failed to load license policies", error);
    } finally {
      setLicensePoliciesLoading(false);
    }
  };

  const resetLpForm = () => {
    setLpFormName("");
    setLpFormDescription("");
    setLpFormAllowed("");
    setLpFormDenied("");
    setLpFormDefaultAction("warn");
    setLpFormIsDefault(false);
    setLpEditing(null);
    setLpCreating(false);
  };

  const handleCreateLicensePolicy = async () => {
    try {
      await createLicensePolicy({
        name: lpFormName,
        description: lpFormDescription || undefined,
        allowed: lpFormAllowed.split(",").map(s => s.trim()).filter(Boolean),
        denied: lpFormDenied.split(",").map(s => s.trim()).filter(Boolean),
        defaultAction: lpFormDefaultAction,
        isDefault: lpFormIsDefault,
      });
      resetLpForm();
      void loadLicensePolicies();
      showToast(t("Policy created.", "Richtlinie erstellt."));
    } catch (error) {
      showToast(t("Failed to create policy.", "Richtlinie konnte nicht erstellt werden."), "error");
    }
  };

  const handleUpdateLicensePolicy = async () => {
    if (!lpEditing) return;
    try {
      await updateLicensePolicy(lpEditing.id, {
        name: lpFormName,
        description: lpFormDescription || undefined,
        allowed: lpFormAllowed.split(",").map(s => s.trim()).filter(Boolean),
        denied: lpFormDenied.split(",").map(s => s.trim()).filter(Boolean),
        defaultAction: lpFormDefaultAction,
        isDefault: lpFormIsDefault,
      });
      resetLpForm();
      void loadLicensePolicies();
      showToast(t("Policy updated.", "Richtlinie aktualisiert."));
    } catch (error) {
      showToast(t("Failed to update policy.", "Richtlinie konnte nicht aktualisiert werden."), "error");
    }
  };

  const handleDeleteLicensePolicy = async (policyId: string) => {
    try {
      await deleteLicensePolicy(policyId);
      void loadLicensePolicies();
      showToast(t("Policy deleted.", "Richtlinie gelöscht."));
    } catch (error) {
      showToast(t("Failed to delete policy.", "Richtlinie konnte nicht gelöscht werden."), "error");
    }
  };

  const handleSetDefaultPolicy = async (policyId: string) => {
    try {
      await setDefaultLicensePolicy(policyId);
      void loadLicensePolicies();
      showToast(t("Default policy updated.", "Standardrichtlinie aktualisiert."));
    } catch (error) {
      showToast(t("Failed to set default policy.", "Standardrichtlinie konnte nicht gesetzt werden."), "error");
    }
  };

  const startEditingLicensePolicy = (policy: LicensePolicy) => {
    setLpEditing(policy);
    setLpCreating(false);
    setLpFormName(policy.name);
    setLpFormDescription(policy.description || "");
    setLpFormAllowed(policy.allowed.join(", "));
    setLpFormDenied(policy.denied.join(", "));
    setLpFormDefaultAction(policy.defaultAction);
    setLpFormIsDefault(policy.isDefault);
  };

  useEffect(() => {
    void loadNotificationStatus();
    void loadNotifRules();
    void loadChannels();
    void loadTemplates();
    void loadScannerStatus();
    void loadLicensePolicies();
    void fetchScanTargets({ limit: 200 }).then((r) => setScanTargets(r.items)).catch(() => {});
    void fetchInventoryItems().then((r) => setInventoryItems(r.items)).catch(() => {});
  }, []);

  useEffect(() => {
    void loadSyncStates();
    // Fall back to polling when SSE is not connected
    syncIntervalRef.current = window.setInterval(() => {
      void loadSyncStates();
    }, sseConnected ? 30000 : 5000);

    return () => {
      if (syncIntervalRef.current !== null) {
        window.clearInterval(syncIntervalRef.current);
        syncIntervalRef.current = null;
      }
    };
  }, [sseConnected]);

  // Refresh sync states immediately when SSE events arrive
  useEffect(() => {
    if (sseJobs.size > 0) {
      void loadSyncStates();
    }
  }, [sseJobs]);

  const handleRestore = async (dataset: BackupDataset, file: File) => {
    setBusyId(dataset.id);
    try {
      const fileContent = await file.text();
      const payload = JSON.parse(fileContent);

      if (!payload || typeof payload !== "object") {
        throw new Error(t("Invalid backup format.", "Ungültiges Backup-Format."));
      }

      if (!("metadata" in payload) || typeof (payload as { metadata?: unknown }).metadata !== "object" || payload.metadata == null) {
        throw new Error(t("Backup does not contain metadata.", "Backup enthält keine Metadaten."));
      }

      let summary;
      if (dataset.type === "vuln") {
        const meta = payload.metadata as { source?: string; dataset?: string };
        if (typeof meta.source !== "string") {
          throw new Error(t("Backup does not contain source information.", "Backup enthält keine Source-Information."));
        }
        const backupSource = meta.source.toUpperCase();
        if (!["ALL", "NVD", "EUVD"].includes(backupSource)) {
          throw new Error(t(`Invalid backup source: ${meta.source}.`, `Ungültige Backup-Quelle: ${meta.source}.`));
        }
        summary = await restoreVulnerabilityBackup("ALL", payload);
      } else if (dataset.type === "inventory") {
        const meta = payload.metadata as { dataset?: string };
        if (meta.dataset !== "inventory") {
          throw new Error(t("Backup does not contain inventory items.", "Backup enthält keine Inventar-Einträge."));
        }
        summary = await restoreInventoryBackup(payload);
      } else {
        const meta = payload.metadata as { dataset?: string };
        if (meta.dataset !== "saved_searches") {
          throw new Error(t("Backup does not contain saved searches.", "Backup enthält keine gespeicherten Suchen."));
        }
        summary = await restoreSavedSearchesBackup(payload);
        void refreshSavedSearches();
      }

      showToast(
        t(
          `${dataset.label}: ${summary.inserted} inserted, ${summary.updated} updated, ${summary.skipped} skipped.`,
          `${dataset.label}: ${summary.inserted} neu, ${summary.updated} aktualisiert, ${summary.skipped} übersprungen.`
        ),
        "success"
      );
    } catch (error) {
      console.error("Backup restore failed", error);
      const message =
        error instanceof Error
          ? error.message
          : t(
              `Restore for ${dataset.label} failed.`,
              `Wiederherstellung für ${dataset.label} ist fehlgeschlagen.`
            );
      showToast(message, "error");
    } finally {
      setBusyId(null);
    }
  };


  const parseResyncIds = (input: string): string[] => {
    return input
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  };

  const handleResync = async (deleteOnly: boolean = false) => {
    const ids = parseResyncIds(resyncInput);
    if (ids.length === 0) return;
    setResyncBusy(true);
    try {
      const result = await resyncVulnerabilities(ids, deleteOnly);
      if (result.deleted === 0 && result.errors.length === 0) {
        showToast(result.message, "error");
      } else {
        const parts: string[] = [result.message];
        if (result.errors.length > 0) {
          parts.push(`${result.errors.length} error(s).`);
        }
        showToast(parts.join(" "), result.errors.length > 0 ? "error" : "success");
        if (result.errors.length === 0) setResyncInput("");
      }
    } catch (error) {
      console.error("Resync failed", error);
      showToast(t("Operation failed.", "Vorgang fehlgeschlagen."), "error");
    } finally {
      setResyncBusy(false);
    }
  };

  const startEditSearch = (search: SavedSearch) => {
    setEditingSearchId(search.id);
    setEditName(search.name);
    setEditDqlQuery(search.dqlQuery || "");
    setEditQueryParams(search.queryParams || "");
  };

  const cancelEditSearch = () => {
    setEditingSearchId(null);
  };

  const handleSaveSearch = async () => {
    if (!editingSearchId) return;
    setEditSaving(true);
    try {
      const payload: Record<string, string | null> = { name: editName.trim() };
      if (editDqlQuery.trim()) {
        payload.dqlQuery = editDqlQuery.trim();
      } else {
        payload.queryParams = editQueryParams.trim();
        payload.dqlQuery = null;
      }
      await updateSavedSearch(editingSearchId, payload);
      setEditingSearchId(null);
      showToast(t("Search updated.", "Suche aktualisiert."), "success");
    } catch (error) {
      console.error("Failed to update saved search", error);
      showToast(t("Search could not be updated.", "Suche konnte nicht aktualisiert werden."), "error");
    } finally {
      setEditSaving(false);
    }
  };

  const handleDeleteSavedSearch = async (search: SavedSearch) => {
    setDeletePendingId(search.id);
    try {
      await removeSavedSearch(search.id);
      showToast(t(`Search "${search.name}" deleted.`, `Suche "${search.name}" gelöscht.`), "success");
    } catch (error) {
      console.error("Failed to delete saved search", error);
      showToast(
        t(`Search "${search.name}" could not be deleted.`, `Suche "${search.name}" konnte nicht gelöscht werden.`),
        "error"
      );
    } finally {
      setDeletePendingId(null);
    }
  };

  const triggerRestoreDialog = (datasetId: string) => {
    const input = fileInputs.current[datasetId];
    input?.click();
  };

  const handleFileSelection = (dataset: BackupDataset, event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      void handleRestore(dataset, file);
    }
    event.target.value = "";
  };

  const handleTriggerSync = async (syncType: "euvd" | "nvd" | "cpe" | "kev" | "cwe" | "capec" | "circl" | "ghsa" | "osv", initial: boolean) => {
    const syncId = `${syncType}_${initial ? "initial" : "normal"}`;
    setSyncTriggeringId(syncId);
    try {
      let response;
      switch (syncType) {
        case "euvd":
          response = await triggerEuvdSync(initial);
          break;
        case "nvd":
          response = await triggerNvdSync(initial);
          break;
        case "cpe":
          response = await triggerCpeSync(initial);
          break;
        case "kev":
          response = await triggerKevSync(initial);
          break;
        case "cwe":
          response = await triggerCweSync(initial);
          break;
        case "capec":
          response = await triggerCapecSync(initial);
          break;
        case "circl":
          response = await triggerCirclSync();
          break;
        case "ghsa":
          response = await triggerGhsaSync(initial);
          break;
        case "osv":
          response = await triggerOsvSync(initial);
          break;
      }
      showToast(response.message, "success");
      void loadSyncStates();
    } catch (error) {
      console.error("Failed to trigger sync", error);
      showToast(t("Could not start sync.", "Sync konnte nicht gestartet werden."), "error");
    } finally {
      setSyncTriggeringId(null);
    }
  };

  const getStatusTone = (status: string): StatusTone => {
    switch (status) {
      case "running":
        return "info";
      case "completed":
        return "ok";
      case "failed":
        return "error";
      default:
        return "muted";
    }
  };

  const getStatusLabel = (status: string): string => {
    switch (status) {
      case "running":
        return t("Running", "Läuft");
      case "completed":
        return t("Completed", "Abgeschlossen");
      case "failed":
        return t("Failed", "Fehlgeschlagen");
      default:
        return t("Idle", "Inaktiv");
    }
  };

  const formatDuration = (seconds?: number | null): string => {
    if (!seconds) return "n/a";
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${Math.round(seconds / 3600)}h`;
  };

  const displayedSyncStates = useMemo(() => {
    const order = [
      "euvd_ingestion",
      "euvd_initial_sync",
      "nvd_sync",
      "nvd_initial_sync",
      "cpe_sync",
      "cpe_initial_sync",
      "kev_sync",
      "kev_initial_sync",
      "cwe_sync",
      "cwe_initial_sync",
      "capec_sync",
      "capec_initial_sync",
      "circl_sync",
      "ghsa_sync",
      "ghsa_initial_sync",
      "osv_sync",
      "osv_initial_sync",
    ];
    return syncStates.sort((a: SyncState, b: SyncState) => order.indexOf(a.jobName) - order.indexOf(b.jobName));
  }, [syncStates]);

  const serviceTone = (service: { enabled: boolean; reachable: boolean }): StatusTone => {
    if (!service.enabled) return "muted";
    return service.reachable ? "ok" : "error";
  };

  const serviceLabel = (service: { enabled: boolean; reachable: boolean }): string => {
    if (!service.enabled) return t("Disabled", "Deaktiviert");
    return service.reachable ? t("Connected", "Verbunden") : t("Unreachable", "Nicht erreichbar");
  };

  return (
    <>
    {authRequired && !authOk ? (
      <div className="dialog-overlay system-overlay" onClick={() => navigate(-1)}>
        <div className="dialog" onClick={(e) => e.stopPropagation()}>
          <h1 className="system-gate-title">{t("System Password", "System-Passwort")}</h1>
          <p>{t("Enter the password to access this page.", "Passwort eingeben, um auf diese Seite zuzugreifen.")}</p>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void handleAuthSubmit(); else if (e.key === "Escape") navigate(-1); }}
            placeholder={t("Password", "Passwort")}
            aria-label={t("Password", "Passwort")}
            autoFocus
          />
          <div className="dialog-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate(-1)}
            >
              {t("Cancel", "Abbrechen")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleAuthSubmit()}
              disabled={authChecking || !authPassword}
            >
              {authChecking ? t("Checking...", "Prüfe…") : t("Unlock", "Entsperren")}
            </button>
          </div>
        </div>
      </div>
    ) : authRequired === null ? (
      <div className="dialog-overlay system-overlay">
        <div className="dialog">
          <p className="muted">{t("Loading...", "Laden…")}</p>
        </div>
      </div>
    ) : (
    <div className="page system-page">
      <PageHeader
        title="System"
        description={t(
          "Manage system settings, data sources, notifications, and policies.",
          "Systemeinstellungen, Datenquellen, Benachrichtigungen und Richtlinien verwalten."
        )}
      />
      <div className="tabs-scroll system-tabs">
        {([
          { key: "general" as SystemTab, label: t("General", "Allgemein") },
          { key: "access" as SystemTab, label: t("Access Control", "Zugriffskontrolle") },
          { key: "notifications" as SystemTab, label: t("Notifications", "Benachrichtigungen") },
          { key: "data" as SystemTab, label: t("Data", "Daten") },
          { key: "policies" as SystemTab, label: t("Policies", "Richtlinien") },
        ]).map(({ key, label }) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            style={tabPillStyle(tab === key)}
            aria-current={tab === key ? "true" : undefined}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "general" && (<>
      <Section title={t("Services", "Dienste")}>
        <p className="system-section-help">
          {t(
            "Connection status of external services used by Hecate.",
            "Verbindungsstatus der von Hecate verwendeten externen Dienste."
          )}
        </p>
        {/* Apprise (Notifications) */}
        {notifLoading ? (
          <RowsSkeleton rows={1} label={t("Loading...", "Laden…")} />
        ) : notifStatus ? (
          <Setting label="Apprise">
            <StatusWord tone={serviceTone(notifStatus)}>{serviceLabel(notifStatus)}</StatusWord>
            <input
              type="text"
              className="system-input system-input--tag"
              value={notifTestTag}
              onChange={(e) => setNotifTestTag(e.target.value)}
              placeholder="Tag"
              aria-label="Tag"
              disabled={!notifStatus.enabled}
            />
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void handleTestNotification()}
              disabled={notifTestBusy || !notifStatus.enabled}
            >
              {notifTestBusy ? "..." : t("Test", "Test")}
            </button>
          </Setting>
        ) : null}

        {/* Scanner */}
        {scannerLoading ? (
          <RowsSkeleton rows={1} label={t("Loading...", "Laden…")} />
        ) : scannerStatus ? (
          <Setting label="Scanner">
            <StatusWord tone={serviceTone(scannerStatus)}>{serviceLabel(scannerStatus)}</StatusWord>
          </Setting>
        ) : null}
      </Section>

      <Section title={t("Language and timezone", "Sprache und Zeitzone")}>
        <Setting
          label={t("Interface language", "Oberflächensprache")}
          help={t(
            "The initial default follows your browser language. Set a fixed language here.",
            "Die initiale Standardsprache folgt der Browser-Sprache. Hier kannst du eine feste Sprache setzen."
          )}
          htmlFor="system-language-select"
        >
          <select
            id="system-language-select"
            className="system-input"
            value={language}
            onChange={(event) => setLanguage(event.target.value as AppLanguage)}
          >
            <option value="en">English</option>
            <option value="de">Deutsch</option>
          </select>
        </Setting>

        <Setting
          label={t("Display timezone", "Anzeige-Zeitzone")}
          help={t(
            "All dates in the UI are rendered in this timezone. Defaults to your browser's timezone.",
            "Alle Datumsangaben werden in dieser Zeitzone dargestellt. Standard ist die Zeitzone deines Browsers."
          )}
          htmlFor="system-timezone-input"
        >
          <input
            id="system-timezone-input"
            className="system-input"
            list="system-timezone-options"
            value={timezoneDraft}
            placeholder={t(`Browser default (${timezone})`, `Browser-Standard (${timezone})`)}
            onChange={(event) => {
              const next = event.target.value;
              setTimezoneDraft(next);
              const trimmed = next.trim();
              if (!trimmed) {
                setTimezone(null);
                return;
              }
              if (supportedTimezones.includes(trimmed)) {
                setTimezone(trimmed);
              }
            }}
            onBlur={() => {
              const trimmed = timezoneDraft.trim();
              if (!trimmed) {
                setTimezone(null);
                return;
              }
              if (!supportedTimezones.includes(trimmed)) {
                // invalid entry — snap back to committed value
                setTimezoneDraft(isBrowserDefault ? "" : timezone);
              }
            }}
          />
          <datalist id="system-timezone-options">
            {supportedTimezones.map((tz) => (
              <option key={tz} value={tz} />
            ))}
          </datalist>
          {!isBrowserDefault && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setTimezone(null)}
            >
              {t("Reset to browser default", "Auf Browser-Standard zurücksetzen")}
            </button>
          )}
          <p className="system-setting-note">
            {t(
              `Active timezone: ${timezone}${isBrowserDefault ? " (browser default)" : ""}`,
              `Aktive Zeitzone: ${timezone}${isBrowserDefault ? " (Browser-Standard)" : ""}`
            )}
          </p>
        </Setting>
      </Section>

      <Section title={t("AI analysis", "AI-Analyse")}>
        <Setting
          label={t("Batch limit", "Batch-Limit")}
          help={t(
            "Maximum number of vulnerabilities that can be analyzed together in one AI batch.",
            "Maximale Anzahl an Schwachstellen, die zusammen in einer AI-Batch-Analyse ausgewertet werden können."
          )}
          htmlFor="ai-batch-limit-input"
        >
          <input
            id="ai-batch-limit-input"
            className="system-input system-input--number"
            type="number"
            min={1}
            max={100}
            value={aiBatchDraft}
            onChange={(event) => setAiBatchDraft(event.target.value)}
          />
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void handleSaveAiBatchLimit()}
            disabled={aiBatchSaving}
          >
            {aiBatchSaving ? t("Saving…", "Speichere…") : t("Save", "Speichern")}
          </button>
        </Setting>
      </Section>

      <Section title={t("Backup & Restore", "Backup & Restore")}>
        <p className="system-section-help">
          {t(
            "Download source backups or restore previously exported backup files.",
            "Lade Sicherungen der Datenquellen herunter oder spiele zuvor exportierte Backups wieder ein."
          )}
        </p>
        {backupDatasets.map((dataset) => (
          <Setting key={dataset.id} label={dataset.label} help={dataset.description}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void handleExport(dataset)}
              disabled={busyId === dataset.id}
            >
              {busyId === dataset.id ? t("Please wait...", "Bitte warten…") : t("Download backup", "Backup herunterladen")}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => triggerRestoreDialog(dataset.id)}
              disabled={busyId === dataset.id}
            >
              {t("Restore...", "Wiederherstellen…")}
            </button>
            <input
              type="file"
              accept="application/json"
              hidden
              ref={(element) => {
                fileInputs.current[dataset.id] = element;
              }}
              onChange={(event) => handleFileSelection(dataset, event)}
            />
          </Setting>
        ))}
      </Section>
      </>)}

      {tab === "access" && (<>
      <ApiTokenPanel />
      <TargetAccessPanel />
      </>)}

      {tab === "notifications" && (<>
      <Section
        title={t("Notification channels", "Benachrichtigungskanäle")}
        actions={
          <button type="button" className="btn btn-secondary" onClick={() => setShowChannelForm(true)}>
            <LuPlus aria-hidden="true" />
            {t("Add Channel", "Kanal hinzufügen")}
          </button>
        }
      >
        <p className="system-section-help">
          {t(
            "Configure where notifications are sent (e.g. email, Slack, Signal, webhooks). Each channel can be tagged for rule-based routing.",
            "Konfiguriere, wohin Benachrichtigungen gesendet werden (z.B. E-Mail, Slack, Signal, Webhooks). Jeder Kanal kann für regelbasiertes Routing getaggt werden."
          )}
        </p>

        {showChannelForm && (
          <div className="well system-form">
            <Setting
              label={t("Apprise URL", "Apprise-URL")}
              help={
                <>
                  {t("See ", "Siehe ")}<a href="https://github.com/caronc/apprise/wiki" target="_blank" rel="noopener noreferrer">Apprise Wiki</a>{t(" for all supported URL formats (90+ services).", " für alle unterstützten URL-Formate (90+ Dienste).")}
                </>
              }
              htmlFor="system-channel-url"
            >
              <input
                id="system-channel-url"
                type="text"
                className="system-input mono"
                value={channelUrl}
                onChange={(e) => setChannelUrl(e.target.value)}
                placeholder={t("e.g. slack://TokenA/TokenB/TokenC or mailto://user:pass@gmail.com", "z.B. slack://TokenA/TokenB/TokenC oder mailto://user:pass@gmail.com")}
              />
            </Setting>
            <Setting
              label={t("Tag (optional)", "Tag (optional)")}
              help={t(
                "Assign a tag to route this channel via notification rules.",
                "Weise einen Tag zu, um diesen Kanal über Benachrichtigungsregeln zu steuern."
              )}
              htmlFor="system-channel-tag"
            >
              <input
                id="system-channel-tag"
                type="text"
                className="system-input"
                value={channelTag}
                onChange={(e) => setChannelTag(e.target.value)}
                placeholder={t("e.g. email, slack, signal", "z.B. email, slack, signal")}
              />
            </Setting>
            <div className="system-form-actions">
              <button type="button" className="btn btn-primary" onClick={() => void handleAddChannel()} disabled={channelSaving || !channelUrl.trim()}>
                {channelSaving ? t("Saving...", "Speichern…") : t("Add Channel", "Kanal hinzufügen")}
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => { setShowChannelForm(false); setChannelUrl(""); setChannelTag(""); }}>
                {t("Cancel", "Abbrechen")}
              </button>
            </div>
          </div>
        )}

        {channelsLoading ? (
          <RowsSkeleton rows={2} label={t("Loading channels...", "Lade Kanäle…")} />
        ) : channels.length === 0 ? (
          <EmptyState title={t("No notification channels configured yet.", "Noch keine Benachrichtigungskanäle konfiguriert.")}>
            {t("Add a channel to receive notifications.", "Füge einen Kanal hinzu, um Benachrichtigungen zu empfangen.")}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="system-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>{t("Tag", "Tag")}</th>
                  <th className="system-cell-action">{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {channels.map((ch) => (
                  <tr key={ch.id}>
                    <td className="system-cell-name"><code className="system-code">{ch.url}</code></td>
                    <td data-label={t("Tag", "Tag")}><span className="mono">{ch.tag}</span></td>
                    <td className="system-cell-action">
                      <button
                        type="button"
                        className="btn btn-secondary system-btn-danger"
                        onClick={() => void handleRemoveChannel(ch.id)}
                        disabled={channelRemovingId === ch.id}
                      >
                        {channelRemovingId === ch.id ? "..." : t("Remove", "Entfernen")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        title={t("Notification rules", "Benachrichtigungsregeln")}
        actions={
          <button type="button" className="btn btn-secondary" onClick={() => openRuleForm()}>
            <LuPlus aria-hidden="true" />
            {t("Add Rule", "Regel hinzufügen")}
          </button>
        }
      >
        <p className="system-section-help">
          {t(
            "Configure which events and vulnerability matches trigger notifications and to which channels (Apprise tags).",
            "Konfiguriere, welche Ereignisse und Schwachstellen-Treffer Benachrichtigungen auslösen und an welche Kanäle (Apprise-Tags) sie gesendet werden."
          )}
        </p>

        {showRuleForm && (
          <div className="well system-form">
            <Setting label={t("Name", "Name")} htmlFor="system-rule-name">
              <input
                id="system-rule-name"
                type="text"
                className="system-input"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder={t("Rule name", "Regelname")}
              />
            </Setting>
            <Setting label={t("Type", "Typ")} htmlFor="system-rule-type">
              <select
                id="system-rule-type"
                className="system-input"
                value={formType}
                onChange={(e) => setFormType(e.target.value as NotificationRuleType)}
              >
                <option value="event">{t("System Event", "System-Ereignis")}</option>
                <option value="saved_search">{t("Saved Search", "Gespeicherte Suche")}</option>
                <option value="vendor">{t("Vendor", "Hersteller")}</option>
                <option value="product">{t("Product", "Produkt")}</option>
                <option value="dql">{t("DQL Query", "DQL-Abfrage")}</option>
                <option value="scan">{t("SCA Scan", "SCA-Scan")}</option>
                <option value="inventory">{t("Inventory", "Inventar")}</option>
                <option value="sca_malware_alert">{t("SCA Malware Alert", "SCA-Malware-Alarm")}</option>
              </select>
            </Setting>
            <Setting
              label={t("Apprise Tag", "Apprise-Tag")}
              help={t("Must match a channel tag above.", "Muss einem Kanal-Tag oben entsprechen.")}
              htmlFor="system-rule-tag"
            >
              <input
                id="system-rule-tag"
                type="text"
                className="system-input"
                value={formTag}
                onChange={(e) => setFormTag(e.target.value)}
                placeholder="all"
              />
            </Setting>

            {formType === "event" && (
              <Setting label={t("Event Types", "Ereignistypen")}>
                {["scan_completed", "scan_failed", "sync_failed", "new_vulnerabilities"].map((evt) => (
                  <label key={evt} className="system-check">
                    <input
                      type="checkbox"
                      checked={formEventTypes.includes(evt)}
                      onChange={() => toggleEventType(evt)}
                    />
                    <span className="mono">{evt}</span>
                  </label>
                ))}
              </Setting>
            )}

            {formType === "saved_search" && (
              <Setting label={t("Saved Search", "Gespeicherte Suche")} htmlFor="system-rule-saved-search">
                <select
                  id="system-rule-saved-search"
                  className="system-input"
                  value={formSavedSearchId}
                  onChange={(e) => setFormSavedSearchId(e.target.value)}
                >
                  <option value="">{t("Select...", "Auswählen...")}</option>
                  {sortedSavedSearches.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
              </Setting>
            )}

            {formType === "vendor" && (
              <Setting label={t("Vendor Slug", "Hersteller-Slug")} htmlFor="system-rule-vendor">
                <input
                  id="system-rule-vendor"
                  type="text"
                  className="system-input mono"
                  value={formVendorSlug}
                  onChange={(e) => setFormVendorSlug(e.target.value)}
                  placeholder={t("e.g. microsoft", "z.B. microsoft")}
                />
              </Setting>
            )}

            {formType === "product" && (
              <Setting label={t("Product Slug", "Produkt-Slug")} htmlFor="system-rule-product">
                <input
                  id="system-rule-product"
                  type="text"
                  className="system-input mono"
                  value={formProductSlug}
                  onChange={(e) => setFormProductSlug(e.target.value)}
                  placeholder={t("e.g. windows_10", "z.B. windows_10")}
                />
              </Setting>
            )}

            {formType === "dql" && (
              <Setting label={t("DQL Query", "DQL-Abfrage")} htmlFor="system-rule-dql">
                <input
                  id="system-rule-dql"
                  type="text"
                  className="system-input system-input--wide mono"
                  value={formDqlQuery}
                  onChange={(e) => setFormDqlQuery(e.target.value)}
                  placeholder={t("e.g. severity:critical AND vendors:microsoft", "z.B. severity:critical AND vendors:microsoft")}
                />
              </Setting>
            )}

            {(formType === "scan" || formType === "sca_malware_alert") && (
              <>
                <Setting
                  label={t("Severity Threshold", "Schweregrad-Schwelle")}
                  help={t("Only notify when findings at this severity or above exist.", "Nur benachrichtigen wenn Findings mit diesem Schweregrad oder höher existieren.")}
                  htmlFor="system-rule-severity"
                >
                  <select
                    id="system-rule-severity"
                    className="system-input"
                    value={formScanSeverityThreshold}
                    onChange={(e) => setFormScanSeverityThreshold(e.target.value)}
                  >
                    <option value="">{t("Any (all scans)", "Alle (jeder Scan)")}</option>
                    <option value="critical">{t("Critical", "Kritisch")}</option>
                    <option value="high">{t("High or above", "Hoch oder höher")}</option>
                    <option value="medium">{t("Medium or above", "Mittel oder höher")}</option>
                    <option value="low">{t("Low or above", "Niedrig oder höher")}</option>
                  </select>
                </Setting>
                <Setting
                  label={t("Target", "Ziel")}
                  help={t("Leave empty to match all targets.", "Leer lassen für alle Ziele.")}
                  htmlFor="system-rule-target"
                >
                  <select
                    id="system-rule-target"
                    className="system-input"
                    value={formScanTargetFilter}
                    onChange={(e) => setFormScanTargetFilter(e.target.value)}
                  >
                    <option value="">{t("All targets", "Alle Ziele")}</option>
                    {scanTargets.map((tgt) => (
                      <option key={tgt.id} value={tgt.name}>{tgt.name}</option>
                    ))}
                  </select>
                </Setting>
              </>
            )}

            {formType === "inventory" && (
              <Setting
                label={t("Inventory Items (leave empty = all)", "Inventar-Einträge (leer = alle)")}
                help={t(
                  "Fires when a newly published vulnerability affects the selected items. Leave empty to watch all inventory entries. Hold Ctrl/Cmd to select multiple.",
                  "Löst aus, sobald eine neu veröffentlichte Schwachstelle die ausgewählten Einträge betrifft. Leer lassen, um alle Inventar-Einträge zu beobachten. Mehrfachauswahl mit Strg/Cmd.",
                )}
                htmlFor={inventoryItems.length === 0 ? undefined : "system-rule-inventory"}
              >
                {inventoryItems.length === 0 ? (
                  <p className="system-setting-note">
                    {t(
                      "No inventory items yet. The rule will still work (global scope) once you add items on the Inventory page.",
                      "Noch keine Inventar-Einträge. Die Regel funktioniert dennoch (global), sobald Sie auf der Inventar-Seite Einträge hinzufügen.",
                    )}
                  </p>
                ) : (
                  <select
                    id="system-rule-inventory"
                    className="system-input system-input--wide"
                    multiple
                    value={formInventoryItemIds}
                    onChange={(e) =>
                      setFormInventoryItemIds(
                        Array.from(e.target.selectedOptions).map((o) => o.value),
                      )
                    }
                    size={Math.min(8, Math.max(3, inventoryItems.length))}
                  >
                    {inventoryItems.map((item) => {
                      const vendor = item.vendorName || item.vendorSlug;
                      const product = item.productName || item.productSlug;
                      return (
                        <option key={item.id} value={item.id}>
                          {item.name}: {vendor}/{product} {item.version}
                        </option>
                      );
                    })}
                  </select>
                )}
              </Setting>
            )}

            <Setting label={t("Enabled", "Aktiviert")} htmlFor="system-rule-enabled">
              <input
                id="system-rule-enabled"
                type="checkbox"
                checked={formEnabled}
                onChange={() => setFormEnabled(!formEnabled)}
              />
            </Setting>

            <div className="system-form-actions">
              <button type="button" className="btn btn-primary" onClick={() => void handleSaveRule()} disabled={ruleSaving || !formName.trim()}>
                {ruleSaving
                  ? t("Saving...", "Speichern…")
                  : editingRule
                    ? t("Update Rule", "Regel aktualisieren")
                    : t("Create Rule", "Regel erstellen")}
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => { setShowRuleForm(false); resetRuleForm(); }}>
                {t("Cancel", "Abbrechen")}
              </button>
            </div>
          </div>
        )}

        {notifRulesLoading ? (
          <RowsSkeleton rows={3} label={t("Loading rules...", "Lade Regeln…")} />
        ) : notifRules.length === 0 ? (
          <EmptyState title={t("No notification rules configured yet.", "Noch keine Benachrichtigungsregeln konfiguriert.")} />
        ) : (
          <div className="table-scroll">
            <table className="system-table">
              <thead>
                <tr>
                  <th>{t("Name", "Name")}</th>
                  <th>{t("Type", "Typ")}</th>
                  <th>{t("Details", "Details")}</th>
                  <th>{t("Tag", "Tag")}</th>
                  <th>{t("Status", "Status")}</th>
                  <th>{t("Last triggered", "Zuletzt ausgelöst")}</th>
                  <th className="system-cell-action">{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {notifRules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="system-cell-name"><strong>{rule.name}</strong></td>
                    <td className="system-cell-nowrap" data-label={t("Type", "Typ")}>{getRuleTypeLabel(rule.ruleType)}</td>
                    <td className="system-cell-detail" data-label={t("Details", "Details")}>{getRuleDescription(rule)}</td>
                    <td data-label={t("Tag", "Tag")}><span className="mono">{rule.appriseTag}</span></td>
                    <td data-label={t("Status", "Status")}>
                      <button
                        type="button"
                        className={`system-toggle${rule.enabled ? "" : " system-toggle--off"}`}
                        aria-pressed={rule.enabled}
                        onClick={() => void handleToggleRule(rule)}
                      >
                        {rule.enabled ? t("Active", "Aktiv") : t("Disabled", "Deaktiviert")}
                      </button>
                    </td>
                    <td className="system-cell-nowrap" data-label={t("Last triggered", "Zuletzt ausgelöst")}>
                      {rule.lastTriggeredAt ? formatDateTime(rule.lastTriggeredAt) : <span className="muted">n/a</span>}
                    </td>
                    <td className="system-cell-action">
                      <div className="system-row-actions">
                        <button type="button" className="btn btn-secondary" onClick={() => openRuleForm(rule)}>
                          {t("Edit", "Bearbeiten")}
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary system-btn-danger"
                          onClick={() => void handleDeleteRule(rule)}
                          disabled={ruleDeletePendingId === rule.id}
                        >
                          {ruleDeletePendingId === rule.id ? "..." : t("Delete", "Löschen")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        title={t("Message templates", "Nachrichtenvorlagen")}
        actions={
          <button type="button" className="btn btn-secondary" onClick={() => openTemplateForm()}>
            <LuPlus aria-hidden="true" />
            {t("Add Template", "Vorlage hinzufügen")}
          </button>
        }
      >
        <p className="system-section-help">
          {t(
            "Customize notification messages per event type. Use a specific tag to override messages for certain channels, or 'all' for a global default. Templates use {placeholder} variables.",
            "Passe Benachrichtigungstexte pro Ereignistyp an. Verwende einen bestimmten Tag für kanalspezifische Nachrichten oder 'all' als globalen Standard. Vorlagen verwenden {Platzhalter}-Variablen."
          )}
        </p>

        {showTemplateForm && (
          <div className="well system-form">
            <Setting label={t("Event Type", "Ereignistyp")} htmlFor="system-template-event">
              <select
                id="system-template-event"
                className="system-input"
                value={tplEventKey}
                onChange={(e) => {
                  const key = e.target.value as NotificationEventKey;
                  setTplEventKey(key);
                  if (!editingTemplate) {
                    const def = DEFAULT_TEMPLATES[key];
                    setTplTitle(def.title);
                    setTplBody(def.body);
                  }
                }}
              >
                {EVENT_KEY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </Setting>
            <Setting
              label={t("Tag", "Tag")}
              help={t("'all' = global default. Use a channel tag (e.g. email, signal) for channel-specific messages.", "'all' = globaler Standard. Verwende einen Kanal-Tag (z.B. email, signal) für kanalspezifische Nachrichten.")}
              htmlFor="system-template-tag"
            >
              <input
                id="system-template-tag"
                type="text"
                className="system-input"
                value={tplTag}
                onChange={(e) => setTplTag(e.target.value)}
                placeholder="all"
              />
            </Setting>
            <Setting label={t("Title Template", "Titel-Vorlage")} htmlFor="system-template-title">
              <input
                id="system-template-title"
                type="text"
                className="system-input system-input--wide"
                value={tplTitle}
                onChange={(e) => setTplTitle(e.target.value)}
                placeholder={DEFAULT_TEMPLATES[tplEventKey].title}
              />
            </Setting>
            <Setting label={t("Body Template", "Text-Vorlage")} htmlFor="system-template-body">
              <textarea
                id="system-template-body"
                className="system-input system-input--wide system-textarea"
                value={tplBody}
                onChange={(e) => setTplBody(e.target.value)}
                placeholder={DEFAULT_TEMPLATES[tplEventKey].body}
                rows={tplEventKey === "watch_rule_match" ? 8 : 5}
              />
            </Setting>
            <Setting label={t("Placeholders", "Platzhalter")}>
              <code className="system-code">{TEMPLATE_PLACEHOLDERS[tplEventKey].scalars}</code>
            </Setting>
            {TEMPLATE_PLACEHOLDERS[tplEventKey].loops && (
              <Setting label={t("Loop blocks", "Schleifen-Blöcke")}>
                <div className="system-loops">
                  {TEMPLATE_PLACEHOLDERS[tplEventKey].loops!.map((lp) => (
                    <div key={lp.label}>
                      <code className="system-code">{`{#each ${lp.label}}...{/each}`}</code>
                      <p className="system-loop-fields"><code className="system-code">{lp.fields}</code></p>
                    </div>
                  ))}
                </div>
              </Setting>
            )}
            <div className="system-form-actions">
              <button type="button" className="btn btn-primary" onClick={() => void handleSaveTemplate()} disabled={templateSaving || !tplTitle.trim() || !tplBody.trim()}>
                {templateSaving
                  ? t("Saving...", "Speichern…")
                  : editingTemplate
                    ? t("Update Template", "Vorlage aktualisieren")
                    : t("Create Template", "Vorlage erstellen")}
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => { setShowTemplateForm(false); resetTemplateForm(); }}>
                {t("Cancel", "Abbrechen")}
              </button>
            </div>
          </div>
        )}

        {templatesLoading ? (
          <RowsSkeleton rows={2} label={t("Loading templates...", "Lade Vorlagen…")} />
        ) : templates.length === 0 ? (
          <EmptyState title={t("No custom message templates configured.", "Keine benutzerdefinierten Nachrichtenvorlagen konfiguriert.")}>
            {t("Default messages will be used.", "Standardnachrichten werden verwendet.")}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="system-table">
              <thead>
                <tr>
                  <th>{t("Event", "Ereignis")}</th>
                  <th>{t("Tag", "Tag")}</th>
                  <th>{t("Title", "Titel")}</th>
                  <th>{t("Body", "Text")}</th>
                  <th className="system-cell-action">{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {templates.map((tpl) => (
                  <tr key={tpl.id}>
                    <td className="system-cell-name"><strong>{getEventKeyLabel(tpl.eventKey)}</strong></td>
                    <td data-label={t("Tag", "Tag")}><span className="mono">{tpl.tag}</span></td>
                    <td className="system-cell-detail" data-label={t("Title", "Titel")}>{tpl.titleTemplate}</td>
                    <td className="system-cell-detail" data-label={t("Body", "Text")}>
                      {tpl.bodyTemplate.substring(0, 80)}{tpl.bodyTemplate.length > 80 ? "…" : ""}
                    </td>
                    <td className="system-cell-action">
                      <div className="system-row-actions">
                        <button type="button" className="btn btn-secondary" onClick={() => openTemplateForm(tpl)}>
                          {t("Edit", "Bearbeiten")}
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary system-btn-danger"
                          onClick={() => void handleDeleteTemplate(tpl)}
                          disabled={templateDeletePendingId === tpl.id}
                        >
                          {templateDeletePendingId === tpl.id ? "..." : t("Delete", "Löschen")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      </>)}

      {tab === "data" && (<>
      <Section title={t("Sync status", "Sync-Status")}>
        <p className="system-section-help">
          {t(
            "Overview of all data source synchronizations. Auto-refresh every 5 seconds.",
            "Übersicht über alle Datenquellen-Synchronisationen. Automatische Aktualisierung alle 5 Sekunden."
          )}
        </p>
        {syncLoading ? (
          <RowsSkeleton rows={9} label={t("Loading sync status ...", "Lade Sync-Status …")} />
        ) : (
          <div className="table-scroll">
            <table className="system-table">
              <thead>
                <tr>
                  <th>{t("Sync Job", "Sync-Job")}</th>
                  <th>{t("Last run", "Letzter Lauf")}</th>
                  <th>{t("Status", "Status")}</th>
                  <th>{t("Duration", "Dauer")}</th>
                  <th>{t("Next run", "Nächster Lauf")}</th>
                  <th className="system-cell-action">{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {displayedSyncStates.map((sync: SyncState) => {
                  const syncType = sync.jobName.includes("euvd")
                    ? "euvd"
                    : sync.jobName.includes("nvd")
                    ? "nvd"
                    : sync.jobName.includes("cpe")
                    ? "cpe"
                    : sync.jobName.includes("kev")
                    ? "kev"
                    : sync.jobName.includes("capec")
                    ? "capec"
                    : sync.jobName.includes("circl")
                    ? "circl"
                    : sync.jobName.includes("ghsa")
                    ? "ghsa"
                    : sync.jobName.includes("osv")
                    ? "osv"
                    : "cwe";
                  const isInitial = sync.jobName.includes("initial");
                  const syncId = `${syncType}_${isInitial ? "initial" : "normal"}`;
                  const isBusy = syncTriggeringId === syncId || sync.status === "running";
                  const isExpanded = expandedSyncId === sync.jobName;
                  const hasDetails = sync.lastResult || sync.error;
                  // Some jobs are CLI-only (no scheduler / HTTP trigger): hide
                  // the Start-manually affordance so users don't get mis-routed
                  // into a different source's trigger endpoint via the syncType
                  // fallback chain.
                  const canTrigger = !sync.jobName.startsWith("mal_enrichment_backfill");

                  return (
                    <Fragment key={sync.jobName}>
                      <tr
                        className={`${hasDetails ? "system-row--expandable" : ""}${isExpanded ? " system-row--expanded" : ""}`}
                        onClick={() => hasDetails && setExpandedSyncId(isExpanded ? null : sync.jobName)}
                      >
                        <td className="system-cell-name">
                          {/* The row owns the toggle; this button makes it reachable by keyboard. */}
                          {hasDetails ? (
                            <button type="button" className="system-row-toggle" aria-expanded={isExpanded}>
                              <LuChevronRight aria-hidden="true" />
                              {sync.label}
                            </button>
                          ) : (
                            <strong>{sync.label}</strong>
                          )}
                        </td>
                        <td className="system-cell-nowrap" data-label={t("Last run", "Letzter Lauf")}>
                          {sync.startedAt ? formatDateTime(sync.startedAt) : <span className="muted">n/a</span>}
                        </td>
                        <td data-label={t("Status", "Status")}>
                          <StatusWord tone={getStatusTone(sync.status)}>{getStatusLabel(sync.status)}</StatusWord>
                        </td>
                        <td data-label={t("Duration", "Dauer")}>{formatDuration(sync.durationSeconds)}</td>
                        <td className="system-cell-nowrap" data-label={t("Next run", "Nächster Lauf")}>
                          {sync.nextRun ? (
                            formatDateTime(sync.nextRun)
                          ) : isInitial ? (
                            <span className="muted">{t("Only on startup", "Nur bei Start")}</span>
                          ) : (
                            <span className="muted">n/a</span>
                          )}
                        </td>
                        <td className="system-cell-action">
                          {canTrigger ? (
                            <button
                              type="button"
                              className="btn btn-secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                void handleTriggerSync(syncType, isInitial);
                              }}
                              disabled={isBusy}
                            >
                              {isBusy ? t("Starting...", "Wird gestartet…") : t("Start manually", "Manuell starten")}
                            </button>
                          ) : (
                            <span
                              className="muted"
                              title={t(
                                "This job is CLI-only: poetry run python -m app.cli enrich-mal",
                                "Dieser Job läuft nur per CLI: poetry run python -m app.cli enrich-mal",
                              )}
                            >
                              {t("CLI only", "Nur via CLI")}
                            </span>
                          )}
                        </td>
                      </tr>
                      {isExpanded && hasDetails && (
                        <tr className="system-detail-row">
                          <td colSpan={6}>
                            <div className="well">
                              <dl className="system-detail-meta">
                                <div>
                                  <dt>{t("Started", "Gestartet")}</dt>
                                  <dd>{sync.startedAt ? formatDateTime(sync.startedAt) : "n/a"}</dd>
                                </div>
                                <div>
                                  <dt>{t("Finished", "Beendet")}</dt>
                                  <dd>{sync.finishedAt ? formatDateTime(sync.finishedAt) : "n/a"}</dd>
                                </div>
                              </dl>
                              {sync.error ? (
                                <div>
                                  <strong className="system-detail-error">{t("Error:", "Fehler:")}</strong>
                                  <pre className="system-pre system-detail-error">{sync.error}</pre>
                                </div>
                              ) : sync.lastResult ? (
                                <div>
                                  <strong>{t("Last result:", "Letztes Ergebnis:")}</strong>
                                  <pre className="system-pre">{JSON.stringify(sync.lastResult, null, 2)}</pre>
                                </div>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title={t("Vulnerability Re-Sync", "Vulnerability Re-Sync")}>
        <p className="system-section-help">
          {t(
            "Delete vulnerabilities from the database and optionally re-fetch from upstream sources. Supports multiple IDs and wildcard patterns.",
            "Schwachstellen aus der Datenbank löschen und optional von Upstream-Quellen neu abrufen. Mehrere IDs und Wildcards werden unterstützt."
          )}
        </p>
        <div className="system-resync">
          <textarea
            className="system-textarea mono"
            value={resyncInput}
            onChange={(e) => setResyncInput(e.target.value)}
            placeholder={t(
              "One ID per line or comma-separated. Wildcards supported (e.g. CVE-2024-*).\nCVE-2026-34043\nGHSA-qj8w-gfj5-8c6v",
              "Eine ID pro Zeile oder kommagetrennt. Wildcards möglich (z.B. CVE-2024-*).\nCVE-2026-34043\nGHSA-qj8w-gfj5-8c6v"
            )}
            aria-label={t("Vulnerability Re-Sync", "Vulnerability Re-Sync")}
            disabled={resyncBusy}
            rows={3}
          />
          <div className="system-row-actions system-row-actions--start">
            <button
              type="button"
              className="btn btn-secondary system-btn-danger"
              onClick={() => void handleResync(false)}
              disabled={resyncBusy || !resyncInput.trim()}
            >
              {resyncBusy ? t("Processing…", "Verarbeitung…") : t("Delete & Re-Sync", "Löschen & Re-Sync")}
            </button>
            <button
              type="button"
              className="btn btn-secondary system-btn-danger"
              onClick={() => void handleResync(true)}
              disabled={resyncBusy || !resyncInput.trim()}
            >
              {t("Delete Only", "Nur löschen")}
            </button>
          </div>
        </div>
      </Section>

      <Section title={t("Saved searches", "Gespeicherte Suchen")}>
        <p className="system-section-help">
          {t("Manage saved filters for the vulnerabilities view.", "Verwalte gespeicherte Filter für die Vulnerability-Ansicht.")}{" "}
          {t("Total:", "Gesamt:")} {sortedSavedSearches.length.toLocaleString(locale)}.
        </p>
        {savedSearchLoading && sortedSavedSearches.length === 0 ? (
          <RowsSkeleton rows={3} label={t("Loading saved searches ...", "Lade gespeicherte Suchen …")} />
        ) : sortedSavedSearches.length === 0 ? (
          <EmptyState title={t("No saved searches available.", "Es sind keine gespeicherten Suchen vorhanden.")} />
        ) : (
          <div className="table-scroll">
            <table className="system-table">
              <thead>
                <tr>
                  <th>{t("Name", "Name")}</th>
                  <th>{t("Query params", "Suchparameter")}</th>
                  <th>{t("DQL query", "DQL Query")}</th>
                  <th>{t("Created", "Erstellt")}</th>
                  <th className="system-cell-action">{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {sortedSavedSearches.map((search) => {
                  const isEditing = editingSearchId === search.id;
                  return (
                  <Fragment key={search.id}>
                  <tr>
                    <td className="system-cell-name"><strong>{search.name}</strong></td>
                    <td className="system-cell-detail" data-label={t("Query params", "Suchparameter")}>
                      {search.queryParams ? (
                        <code className="system-code">{search.queryParams}</code>
                      ) : (
                        <span className="muted">n/a</span>
                      )}
                    </td>
                    <td className="system-cell-detail" data-label={t("DQL query", "DQL Query")}>
                      {search.dqlQuery ? (
                        <code className="system-code">{search.dqlQuery}</code>
                      ) : (
                        <span className="muted">n/a</span>
                      )}
                    </td>
                    <td className="system-cell-nowrap" data-label={t("Created", "Erstellt")}>
                      {formatDateTime(search.createdAt)}
                    </td>
                    <td className="system-cell-action">
                      <div className="system-row-actions">
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => isEditing ? cancelEditSearch() : startEditSearch(search)}
                          disabled={deletePendingId === search.id}
                        >
                          {isEditing ? t("Cancel", "Abbrechen") : t("Edit", "Bearbeiten")}
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary system-btn-danger"
                          onClick={() => void handleDeleteSavedSearch(search)}
                          disabled={deletePendingId === search.id || isEditing}
                        >
                          {deletePendingId === search.id ? t("Deleting…", "Löschen…") : t("Delete", "Löschen")}
                        </button>
                      </div>
                    </td>
                  </tr>
                  {isEditing && (
                    <tr className="system-detail-row">
                      <td colSpan={5}>
                        <div className="well system-form">
                          <Setting label={t("Name", "Name")} htmlFor="system-search-name">
                            <input
                              id="system-search-name"
                              type="text"
                              className="system-input"
                              value={editName}
                              onChange={(e) => setEditName(e.target.value)}
                            />
                          </Setting>
                          {search.dqlQuery ? (
                            <Setting label="DQL Query" htmlFor="system-search-dql">
                              <input
                                id="system-search-dql"
                                type="text"
                                className="system-input system-input--wide mono"
                                value={editDqlQuery}
                                onChange={(e) => setEditDqlQuery(e.target.value)}
                              />
                            </Setting>
                          ) : (
                            <Setting label={t("Query Params", "Suchparameter")} htmlFor="system-search-params">
                              <input
                                id="system-search-params"
                                type="text"
                                className="system-input system-input--wide mono"
                                value={editQueryParams}
                                onChange={(e) => setEditQueryParams(e.target.value)}
                              />
                            </Setting>
                          )}
                          <div className="system-form-actions">
                            <button
                              type="button"
                              className="btn btn-primary"
                              onClick={() => void handleSaveSearch()}
                              disabled={editSaving || !editName.trim()}
                            >
                              {editSaving ? t("Saving…", "Speichern…") : t("Save", "Speichern")}
                            </button>
                            <button
                              type="button"
                              className="btn btn-secondary"
                              onClick={cancelEditSearch}
                              disabled={editSaving}
                            >
                              {t("Cancel", "Abbrechen")}
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                  </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      </>)}

      {tab === "policies" && (
      <Section
        title={t("License policies", "Lizenzrichtlinien")}
        actions={
          !lpCreating && !lpEditing ? (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => { resetLpForm(); setLpCreating(true); }}
            >
              <LuPlus aria-hidden="true" />
              {t("Create Policy", "Richtlinie erstellen")}
            </button>
          ) : undefined
        }
      >
        <p className="system-section-help">
          {t(
            "Define policies to evaluate SBOM component licenses. The default policy is automatically applied after each scan.",
            "Definieren Sie Richtlinien zur Bewertung von SBOM-Komponentenlizenzen. Die Standardrichtlinie wird nach jedem Scan automatisch angewendet."
          )}
        </p>

        {(lpCreating || lpEditing) && (
          <div className="well system-form">
            <h3 className="system-form-title">
              {lpEditing ? t("Edit Policy", "Richtlinie bearbeiten") : t("New Policy", "Neue Richtlinie")}
            </h3>
            <Setting label={t("Name", "Name")} htmlFor="system-policy-name">
              <input id="system-policy-name" type="text" className="system-input" value={lpFormName} onChange={e => setLpFormName(e.target.value)} />
            </Setting>
            <Setting label={t("Description", "Beschreibung")} htmlFor="system-policy-description">
              <input id="system-policy-description" type="text" className="system-input system-input--wide" value={lpFormDescription} onChange={e => setLpFormDescription(e.target.value)} />
            </Setting>
            <Setting
              label={t("Allowed Licenses (comma-separated SPDX IDs)", "Erlaubte Lizenzen (kommagetrennte SPDX-IDs)")}
              htmlFor="system-policy-allowed"
            >
              <input id="system-policy-allowed" type="text" className="system-input system-input--wide mono" value={lpFormAllowed} onChange={e => setLpFormAllowed(e.target.value)} placeholder="MIT, Apache-2.0, BSD-3-Clause, ISC" />
              {licenseGroups && (
                <div className="system-fill-row">
                  <button type="button" className="btn btn-secondary" onClick={() => setLpFormAllowed(licenseGroups.permissive.join(", "))}>
                    {t("Fill: Permissive", "Einfügen: Permissiv")}
                  </button>
                </div>
              )}
            </Setting>
            <Setting
              label={t("Denied Licenses (comma-separated SPDX IDs)", "Verbotene Lizenzen (kommagetrennte SPDX-IDs)")}
              htmlFor="system-policy-denied"
            >
              <input id="system-policy-denied" type="text" className="system-input system-input--wide mono" value={lpFormDenied} onChange={e => setLpFormDenied(e.target.value)} placeholder="GPL-3.0-only, AGPL-3.0-only" />
              {licenseGroups && (
                <div className="system-fill-row">
                  <button type="button" className="btn btn-secondary" onClick={() => setLpFormDenied(licenseGroups.copyleft.join(", "))}>
                    {t("Fill: Copyleft", "Einfügen: Copyleft")}
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={() => setLpFormDenied([...licenseGroups.copyleft, ...licenseGroups.weakCopyleft].join(", "))}>
                    {t("Fill: All Copyleft", "Einfügen: Alle Copyleft")}
                  </button>
                </div>
              )}
            </Setting>
            <Setting
              label={t("Default Action (for unlisted licenses)", "Standardaktion (für nicht gelistete Lizenzen)")}
              htmlFor="system-policy-action"
            >
              <select id="system-policy-action" className="system-input" value={lpFormDefaultAction} onChange={e => setLpFormDefaultAction(e.target.value)}>
                <option value="allow">{t("Allow", "Erlauben")}</option>
                <option value="warn">{t("Warn", "Warnen")}</option>
                <option value="deny">{t("Deny", "Verweigern")}</option>
              </select>
            </Setting>
            <Setting label={t("Set as default policy", "Als Standardrichtlinie festlegen")} htmlFor="system-policy-default">
              <input id="system-policy-default" type="checkbox" checked={lpFormIsDefault} onChange={e => setLpFormIsDefault(e.target.checked)} />
            </Setting>
            <div className="system-form-actions">
              <button
                type="button"
                className="btn btn-primary"
                onClick={lpEditing ? handleUpdateLicensePolicy : handleCreateLicensePolicy}
                disabled={!lpFormName.trim()}
              >
                {lpEditing ? t("Save", "Speichern") : t("Create", "Erstellen")}
              </button>
              <button type="button" className="btn btn-secondary" onClick={resetLpForm}>
                {t("Cancel", "Abbrechen")}
              </button>
            </div>
          </div>
        )}

        {licensePoliciesLoading ? (
          <RowsSkeleton rows={2} label={t("Loading...", "Laden...")} />
        ) : licensePolicies.length === 0 ? (
          <EmptyState title={t("No license policies configured yet.", "Noch keine Lizenzrichtlinien konfiguriert.")} />
        ) : (
          <div className="table-scroll">
            <table className="system-table system-table--stack-actions">
              <thead>
                <tr>
                  <th>{t("Name", "Name")}</th>
                  <th>{t("Allowed", "Erlaubt")}</th>
                  <th>{t("Denied", "Verboten")}</th>
                  <th>{t("Default action", "Standardaktion")}</th>
                  <th className="system-cell-action">{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {licensePolicies.map(policy => (
                  <tr key={policy.id}>
                    <td className="system-cell-name">
                      <div className="system-name-line">
                        <strong>{policy.name}</strong>
                        {policy.isDefault && <span className="tag">{t("Default", "Standard")}</span>}
                      </div>
                      {policy.description && <p className="system-cell-sub">{policy.description}</p>}
                    </td>
                    <td data-label={t("Allowed", "Erlaubt")}>{policy.allowed.length}</td>
                    <td data-label={t("Denied", "Verboten")}>{policy.denied.length}</td>
                    <td data-label={t("Default action", "Standardaktion")}>{policy.defaultAction}</td>
                    <td className="system-cell-action">
                      <div className="system-row-actions">
                        {!policy.isDefault && (
                          <button type="button" className="btn btn-secondary" onClick={() => handleSetDefaultPolicy(policy.id)}>
                            {t("Set Default", "Als Standard")}
                          </button>
                        )}
                        <button type="button" className="btn btn-secondary" onClick={() => startEditingLicensePolicy(policy)}>
                          {t("Edit", "Bearbeiten")}
                        </button>
                        <button type="button" className="btn btn-secondary system-btn-danger" onClick={() => handleDeleteLicensePolicy(policy.id)}>
                          {t("Delete", "Löschen")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      )}
    </div>
    )}
  </>
  );
};
