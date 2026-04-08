import { Fragment, useEffect, useMemo, useRef, useState, type ChangeEvent, type CSSProperties } from "react";
import { useNavigate } from "react-router-dom";

import {
  exportSavedSearchesBackup,
  exportVulnerabilityBackup,
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
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useSSE } from "../hooks/useSSE";
import { useI18n, type TranslateFn } from "../i18n/context";
import type { AppLanguage } from "../i18n/language";
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
} from "../types";
import { formatDateTime } from "../utils/dateFormat";

type SystemTab = "general" | "notifications" | "data" | "policies";

type BackupDataset =
  | { id: "VULNERABILITIES"; label: string; description: string; type: "vuln"; source: VulnerabilitySource }
  | { id: "SAVED_SEARCHES"; label: string; description: string; type: "saved_searches" }

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
    label: t("Saved Searches", "Gespeicherte Suchen"),
    description: t("Backup of all saved search filters", "Sicherung aller gespeicherten Suchfilter"),
    type: "saved_searches"
  }
];

export const SystemPage = () => {
  const { language, locale, setLanguage, t } = useI18n();
  const navigate = useNavigate();

  // --- System password gate ---
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authOk, setAuthOk] = useState(false);
  const [authPassword, setAuthPassword] = useState("");
  const [authError, setAuthError] = useState("");
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
    setAuthError("");
    try {
      const r = await api.post<{ authenticated: boolean }>("/v1/status/system-auth", { password: authPassword });
      if (r.data.authenticated) {
        setAuthOk(true);
      }
    } catch {
      setAuthError(t("Invalid password.", "Falsches Passwort."));
    } finally {
      setAuthChecking(false);
    }
  };

  // --- Regular state ---
  const [busyId, setBusyId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const toastTimeoutRef = useRef<number | null>(null);
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
    }
  };

  const getRuleDescription = (rule: NotificationRule): string => {
    switch (rule.ruleType) {
      case "event": return rule.eventTypes.join(", ") || "-";
      case "saved_search": {
        const search = sortedSavedSearches.find((s) => s.id === rule.savedSearchId);
        return search ? search.name : rule.savedSearchId || "-";
      }
      case "vendor": return rule.vendorSlug || "-";
      case "product": return rule.productSlug || "-";
      case "dql": return rule.dqlQuery?.substring(0, 60) || "-";
    }
  };

  // --- Message Template Handlers ---

  const EVENT_KEY_OPTIONS: { value: NotificationEventKey; label: string }[] = [
    { value: "new_vulnerabilities", label: "New Vulnerabilities" },
    { value: "scan_completed", label: "Scan Completed" },
    { value: "scan_failed", label: "Scan Failed" },
    { value: "sync_failed", label: "Sync Failed" },
    { value: "watch_rule_match", label: "Watch Rule Match" },
  ];

  const TEMPLATE_PLACEHOLDERS: Record<NotificationEventKey, { scalars: string; loop?: string }> = {
    new_vulnerabilities: { scalars: "{icon}, {source}, {count}, {noun}, {time}" },
    scan_completed: { scalars: "{icon}, {target}, {status}, {findings}, {duration}, {scan_id}" },
    scan_failed: { scalars: "{icon}, {target}, {status}, {findings}, {duration}, {scan_id}" },
    sync_failed: { scalars: "{job_name}, {error}, {time}" },
    watch_rule_match: {
      scalars: "{icon}, {rule_name}, {count}, {noun}, {vulnerabilities_list}, {vendors}, {products}, {versions}, {time}",
      loop: "{#each vulnerabilities}{id}, {severity}, {cvss}, {cwes}, {summary}, {title}, {vendors}, {products}, {versions}, {exploited}, {source}, {published}{/each}",
    },
  };

  const DEFAULT_TEMPLATES: Record<NotificationEventKey, { title: string; body: string }> = {
    new_vulnerabilities: {
      title: "{icon} Hecate — {count} New {noun}",
      body: "Source: {source}\nNew entries: {count}\nTime: {time}",
    },
    scan_completed: {
      title: "{icon} Hecate — SCA Scan {status}",
      body: "Target: {target}\nStatus: {status}\nFindings: {findings}\nDuration: {duration}s\nScan ID: {scan_id}",
    },
    scan_failed: {
      title: "{icon} Hecate — SCA Scan {status}",
      body: "Target: {target}\nStatus: {status}\nFindings: {findings}\nDuration: {duration}s\nScan ID: {scan_id}",
    },
    sync_failed: {
      title: "Hecate — Sync Failed: {job_name}",
      body: "Job: {job_name}\nError: {error}\nTime: {time}",
    },
    watch_rule_match: {
      title: "{icon} Hecate — {count} New {noun}: {rule_name}",
      body: "Rule: {rule_name}\nMatches: {count}\nVulnerabilities: {vulnerabilities_list}\nTime: {time}",
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
          : await exportSavedSearchesBackup();

      const timestamp = new Date().toISOString().replace(/[:]/g, "").replace(/\..+/, "");
      const fallbackName =
        dataset.type === "vuln"
          ? `${dataset.source.toLowerCase()}-backup-${timestamp}.json`
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
  }, []);

  useEffect(() => {
    void loadSyncStates();
    // Fall back to polling when SSE is not connected
    syncIntervalRef.current = window.setInterval(() => {
      void loadSyncStates();
    }, sseConnected ? 30000 : 5000);

    return () => {
      if (toastTimeoutRef.current !== null) {
        window.clearTimeout(toastTimeoutRef.current);
        toastTimeoutRef.current = null;
      }
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

  const showToast = (message: string, type: "success" | "error") => {
    if (toastTimeoutRef.current !== null) {
      window.clearTimeout(toastTimeoutRef.current);
      toastTimeoutRef.current = null;
    }
    setToast({ message, type });
    toastTimeoutRef.current = window.setTimeout(() => {
      setToast(null);
      toastTimeoutRef.current = null;
    }, 4000);
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

  const getStatusColor = (status: string): string => {
    switch (status) {
      case "running":
        return "#ffcc66";
      case "completed":
        return "#8fffb0";
      case "failed":
        return "#ffa3a3";
      case "idle":
        return "#888";
      default:
        return "#888";
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
    if (!seconds) return "-";
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

  return (
    <>
    {authRequired && !authOk ? (
      <div className="dialog-overlay" style={{ backdropFilter: "none", WebkitBackdropFilter: "none" }} onClick={() => navigate(-1)}>
        <div className="dialog" onClick={(e) => e.stopPropagation()}>
          <h3>{t("System Password", "System-Passwort")}</h3>
          <p>{t("Enter the password to access this page.", "Passwort eingeben, um auf diese Seite zuzugreifen.")}</p>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void handleAuthSubmit(); else if (e.key === "Escape") navigate(-1); }}
            placeholder={t("Password", "Passwort")}
            autoFocus
          />
          {authError && <p style={{ color: "#ffa3a3", fontSize: "0.85rem", margin: "0.5rem 0 0" }}>{authError}</p>}
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
      <div className="dialog-overlay" style={{ backdropFilter: "none", WebkitBackdropFilter: "none" }}>
        <div className="dialog">
          <p className="muted">{t("Loading...", "Laden…")}</p>
        </div>
      </div>
    ) : (
    <div className="page">
      <section className="card">
      <h2>System</h2>
      <p className="muted">
        {t(
          "Manage system settings, data sources, notifications, and policies.",
          "Systemeinstellungen, Datenquellen, Benachrichtigungen und Richtlinien verwalten."
        )}
      </p>
      <div className="tabs-scroll" style={{ display: "flex", gap: 0, marginTop: "1rem", marginBottom: "1.5rem", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
        {([
          { key: "general" as SystemTab, label: t("General", "Allgemein") },
          { key: "notifications" as SystemTab, label: t("Notifications", "Benachrichtigungen") },
          { key: "data" as SystemTab, label: t("Data", "Daten") },
          { key: "policies" as SystemTab, label: t("Policies", "Richtlinien") },
        ]).map(({ key, label }) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            style={{
              padding: "0.625rem 1.25rem",
              border: "none",
              borderBottom: tab === key ? "2px solid #ffd43b" : "2px solid transparent",
              background: "transparent",
              color: tab === key ? "#ffd43b" : "rgba(255,255,255,0.5)",
              cursor: "pointer",
              fontSize: "0.8125rem",
              fontWeight: tab === key ? 600 : 400,
              transition: "color 0.15s, border-color 0.15s",
              flexShrink: 0,
              whiteSpace: "nowrap",
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "general" && (<>
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Language", "Sprache")}</h2>
        <p className="muted">
          {t(
            "The initial default follows your browser language. Set a fixed language here.",
            "Die initiale Standardsprache folgt der Browser-Sprache. Hier kannst du eine feste Sprache setzen."
          )}
        </p>
        <div style={{ marginTop: "1rem", display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
          <label htmlFor="system-language-select" style={{ fontWeight: 600 }}>
            {t("Interface language", "Oberflächensprache")}
          </label>
          <select
            id="system-language-select"
            value={language}
            onChange={(event) => setLanguage(event.target.value as AppLanguage)}
            style={{ minWidth: "180px", padding: "0.5rem 0.75rem" }}
          >
            <option value="en">🇺🇸 English</option>
            <option value="de">🇩🇪 Deutsch</option>
          </select>
        </div>
      </div>

      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Services", "Dienste")}</h2>
        <p className="muted">
          {t(
            "Connection status of external services used by Hecate.",
            "Verbindungsstatus der von Hecate verwendeten externen Dienste."
          )}
        </p>
        <div style={{ marginTop: "1rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {/* Apprise (Notifications) */}
          {notifLoading ? (
            <p className="muted">{t("Loading...", "Laden…")}</p>
          ) : notifStatus ? (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: "0.75rem",
                padding: "0.6rem 0.75rem",
                borderRadius: "0.4rem",
                background: "rgba(255, 255, 255, 0.02)",
                border: "1px solid rgba(255, 255, 255, 0.06)",
              }}
            >
              <strong style={{ fontSize: "0.85rem", minWidth: "80px" }}>Apprise</strong>
              <span
                style={{
                  display: "inline-block",
                  padding: "0.2rem 0.4rem",
                  borderRadius: "0.3rem",
                  fontSize: "0.8rem",
                  fontWeight: 600,
                  background: notifStatus.enabled
                    ? notifStatus.reachable
                      ? "rgba(143, 255, 176, 0.13)"
                      : "rgba(255, 163, 163, 0.13)"
                    : "rgba(136, 136, 136, 0.13)",
                  color: notifStatus.enabled
                    ? notifStatus.reachable
                      ? "#8fffb0"
                      : "#ffa3a3"
                    : "#888",
                  border: `1px solid ${
                    notifStatus.enabled
                      ? notifStatus.reachable
                        ? "rgba(143, 255, 176, 0.27)"
                        : "rgba(255, 163, 163, 0.27)"
                      : "rgba(136, 136, 136, 0.27)"
                  }`,
                }}
              >
                {notifStatus.enabled
                  ? notifStatus.reachable
                    ? t("Connected", "Verbunden")
                    : t("Unreachable", "Nicht erreichbar")
                  : t("Disabled", "Deaktiviert")}
              </span>
              <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <input
                  type="text"
                  value={notifTestTag}
                  onChange={(e) => setNotifTestTag(e.target.value)}
                  placeholder="Tag"
                  style={{ width: "70px", padding: "0.3rem 0.4rem", fontSize: "0.8rem", boxSizing: "border-box" }}
                  disabled={!notifStatus.enabled}
                />
                <button
                  type="button"
                  onClick={() => void handleTestNotification()}
                  disabled={notifTestBusy || !notifStatus.enabled}
                  style={{ fontSize: "0.8rem", padding: "0.3rem 0.6rem", whiteSpace: "nowrap" }}
                >
                  {notifTestBusy ? "..." : t("Test", "Test")}
                </button>
              </div>
            </div>
          ) : null}

          {/* Scanner */}
          {scannerLoading ? null : scannerStatus ? (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: "0.75rem",
                padding: "0.6rem 0.75rem",
                borderRadius: "0.4rem",
                background: "rgba(255, 255, 255, 0.02)",
                border: "1px solid rgba(255, 255, 255, 0.06)",
              }}
            >
              <strong style={{ fontSize: "0.85rem", minWidth: "80px" }}>Scanner</strong>
              <span
                style={{
                  display: "inline-block",
                  padding: "0.2rem 0.4rem",
                  borderRadius: "0.3rem",
                  fontSize: "0.8rem",
                  fontWeight: 600,
                  background: scannerStatus.enabled
                    ? scannerStatus.reachable
                      ? "rgba(143, 255, 176, 0.13)"
                      : "rgba(255, 163, 163, 0.13)"
                    : "rgba(136, 136, 136, 0.13)",
                  color: scannerStatus.enabled
                    ? scannerStatus.reachable
                      ? "#8fffb0"
                      : "#ffa3a3"
                    : "#888",
                  border: `1px solid ${
                    scannerStatus.enabled
                      ? scannerStatus.reachable
                        ? "rgba(143, 255, 176, 0.27)"
                        : "rgba(255, 163, 163, 0.27)"
                      : "rgba(136, 136, 136, 0.27)"
                  }`,
                }}
              >
                {scannerStatus.enabled
                  ? scannerStatus.reachable
                    ? t("Connected", "Verbunden")
                    : t("Unreachable", "Nicht erreichbar")
                  : t("Disabled", "Deaktiviert")}
              </span>
            </div>
          ) : null}
        </div>
      </div>
      </>)}

      {tab === "notifications" && (<>
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Notification Channels", "Benachrichtigungskanäle")}</h2>
        <p className="muted">
          {t(
            "Configure where notifications are sent (e.g. email, Slack, Signal, webhooks). Each channel can be tagged for rule-based routing.",
            "Konfiguriere, wohin Benachrichtigungen gesendet werden (z.B. E-Mail, Slack, Signal, Webhooks). Jeder Kanal kann für regelbasiertes Routing getaggt werden."
          )}
        </p>

        <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" onClick={() => setShowChannelForm(true)} style={{ fontSize: "0.85rem" }}>
            {t("+ Add Channel", "+ Kanal hinzufügen")}
          </button>
        </div>

        {showChannelForm && (
          <div style={{
            marginTop: "1rem",
            padding: "1rem",
            borderRadius: "0.5rem",
            background: "rgba(255, 255, 255, 0.03)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  {t("Apprise URL", "Apprise-URL")}
                </label>
                <input
                  type="text"
                  value={channelUrl}
                  onChange={(e) => setChannelUrl(e.target.value)}
                  placeholder={t("e.g. slack://TokenA/TokenB/TokenC or mailto://user:pass@gmail.com", "z.B. slack://TokenA/TokenB/TokenC oder mailto://user:pass@gmail.com")}
                  style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                />
                <p className="muted" style={{ margin: "0.25rem 0 0", fontSize: "0.8rem" }}>
                  {t("See ", "Siehe ")}<a href="https://github.com/caronc/apprise/wiki" target="_blank" rel="noopener noreferrer">Apprise Wiki</a>{t(" for all supported URL formats (90+ services).", " für alle unterstützten URL-Formate (90+ Dienste).")}
                </p>
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  {t("Tag (optional)", "Tag (optional)")}
                </label>
                <input
                  type="text"
                  value={channelTag}
                  onChange={(e) => setChannelTag(e.target.value)}
                  placeholder={t("e.g. email, slack, signal", "z.B. email, slack, signal")}
                  style={{ maxWidth: "300px", padding: "0.5rem", boxSizing: "border-box" }}
                />
                <p className="muted" style={{ margin: "0.25rem 0 0", fontSize: "0.8rem" }}>
                  {t(
                    "Assign a tag to route this channel via notification rules.",
                    "Weise einen Tag zu, um diesen Kanal über Benachrichtigungsregeln zu steuern."
                  )}
                </p>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button type="button" onClick={() => void handleAddChannel()} disabled={channelSaving || !channelUrl.trim()} style={{ fontSize: "0.85rem" }}>
                  {channelSaving ? t("Saving...", "Speichern…") : t("Add Channel", "Kanal hinzufügen")}
                </button>
                <button type="button" onClick={() => { setShowChannelForm(false); setChannelUrl(""); setChannelTag(""); }} style={{ fontSize: "0.85rem" }}>
                  {t("Cancel", "Abbrechen")}
                </button>
              </div>
            </div>
          </div>
        )}

        {channelsLoading ? (
          <p className="muted" style={{ marginTop: "1rem" }}>{t("Loading channels...", "Lade Kanäle…")}</p>
        ) : channels.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("No notification channels configured yet. Add a channel to receive notifications.", "Noch keine Benachrichtigungskanäle konfiguriert. Füge einen Kanal hinzu, um Benachrichtigungen zu empfangen.")}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {channels.map((ch) => (
              <div key={ch.id} style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                padding: "0.6rem 0.75rem",
                borderRadius: "0.4rem",
                background: "rgba(255, 255, 255, 0.02)",
                border: "1px solid rgba(255, 255, 255, 0.06)",
                flexWrap: "wrap",
              }}>
                <code style={{ flex: "1 1 auto", fontSize: "0.85rem", wordBreak: "break-all", minWidth: 0 }}>{ch.url}</code>
                <span style={{
                  display: "inline-block",
                  padding: "0.15rem 0.35rem",
                  borderRadius: "0.25rem",
                  fontSize: "0.75rem",
                  background: "rgba(92, 132, 255, 0.1)",
                  color: "#a0b4ff",
                  border: "1px solid rgba(92, 132, 255, 0.2)",
                  flexShrink: 0,
                }}>{ch.tag}</span>
                <button
                  type="button"
                  onClick={() => void handleRemoveChannel(ch.id)}
                  disabled={channelRemovingId === ch.id}
                  style={{ fontSize: "0.8rem", flexShrink: 0 }}
                >
                  {channelRemovingId === ch.id ? "..." : t("Remove", "Entfernen")}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Notification Rules", "Benachrichtigungsregeln")}</h2>
        <p className="muted">
          {t(
            "Configure which events and vulnerability matches trigger notifications and to which channels (Apprise tags).",
            "Konfiguriere, welche Ereignisse und Schwachstellen-Treffer Benachrichtigungen auslösen und an welche Kanäle (Apprise-Tags) sie gesendet werden."
          )}
        </p>

        <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" onClick={() => openRuleForm()} style={{ fontSize: "0.85rem" }}>
            {t("+ Add Rule", "+ Regel hinzufügen")}
          </button>
        </div>

        {showRuleForm && (
          <div style={{
            marginTop: "1rem",
            padding: "1rem",
            borderRadius: "0.5rem",
            background: "rgba(255, 255, 255, 0.03)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  {t("Name", "Name")}
                </label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder={t("Rule name", "Regelname")}
                  style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Type", "Typ")}
                  </label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value as NotificationRuleType)}
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  >
                    <option value="event">{t("System Event", "System-Ereignis")}</option>
                    <option value="saved_search">{t("Saved Search", "Gespeicherte Suche")}</option>
                    <option value="vendor">{t("Vendor", "Hersteller")}</option>
                    <option value="product">{t("Product", "Produkt")}</option>
                    <option value="dql">{t("DQL Query", "DQL-Abfrage")}</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Apprise Tag", "Apprise-Tag")}
                  </label>
                  <input
                    type="text"
                    value={formTag}
                    onChange={(e) => setFormTag(e.target.value)}
                    placeholder="all"
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  />
                  <p className="muted" style={{ margin: "0.25rem 0 0", fontSize: "0.8rem" }}>
                    {t("Must match a channel tag above.", "Muss einem Kanal-Tag oben entsprechen.")}
                  </p>
                </div>
              </div>

              {formType === "event" && (
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.35rem" }}>
                    {t("Event Types", "Ereignistypen")}
                  </label>
                  <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                    {["scan_completed", "scan_failed", "sync_failed", "new_vulnerabilities"].map((evt) => (
                      <label key={evt} style={{ display: "flex", alignItems: "center", gap: "0.3rem", fontSize: "0.85rem", cursor: "pointer" }}>
                        <input
                          type="checkbox"
                          checked={formEventTypes.includes(evt)}
                          onChange={() => toggleEventType(evt)}
                        />
                        {evt}
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {formType === "saved_search" && (
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Saved Search", "Gespeicherte Suche")}
                  </label>
                  <select
                    value={formSavedSearchId}
                    onChange={(e) => setFormSavedSearchId(e.target.value)}
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  >
                    <option value="">{t("Select...", "Auswählen...")}</option>
                    {sortedSavedSearches.map((s) => (
                      <option key={s.id} value={s.id}>{s.name}</option>
                    ))}
                  </select>
                </div>
              )}

              {formType === "vendor" && (
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Vendor Slug", "Hersteller-Slug")}
                  </label>
                  <input
                    type="text"
                    value={formVendorSlug}
                    onChange={(e) => setFormVendorSlug(e.target.value)}
                    placeholder={t("e.g. microsoft", "z.B. microsoft")}
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  />
                </div>
              )}

              {formType === "product" && (
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Product Slug", "Produkt-Slug")}
                  </label>
                  <input
                    type="text"
                    value={formProductSlug}
                    onChange={(e) => setFormProductSlug(e.target.value)}
                    placeholder={t("e.g. windows_10", "z.B. windows_10")}
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  />
                </div>
              )}

              {formType === "dql" && (
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("DQL Query", "DQL-Abfrage")}
                  </label>
                  <input
                    type="text"
                    value={formDqlQuery}
                    onChange={(e) => setFormDqlQuery(e.target.value)}
                    placeholder={t("e.g. severity:critical AND vendors:microsoft", "z.B. severity:critical AND vendors:microsoft")}
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  />
                </div>
              )}

              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "0.3rem", fontSize: "0.85rem", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={formEnabled}
                    onChange={() => setFormEnabled(!formEnabled)}
                  />
                  {t("Enabled", "Aktiviert")}
                </label>
              </div>

              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button type="button" onClick={() => void handleSaveRule()} disabled={ruleSaving || !formName.trim()} style={{ fontSize: "0.85rem" }}>
                  {ruleSaving
                    ? t("Saving...", "Speichern…")
                    : editingRule
                      ? t("Update Rule", "Regel aktualisieren")
                      : t("Create Rule", "Regel erstellen")}
                </button>
                <button type="button" onClick={() => { setShowRuleForm(false); resetRuleForm(); }} style={{ fontSize: "0.85rem" }}>
                  {t("Cancel", "Abbrechen")}
                </button>
              </div>
            </div>
          </div>
        )}

        {notifRulesLoading ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("Loading rules...", "Lade Regeln…")}
          </p>
        ) : notifRules.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("No notification rules configured yet.", "Noch keine Benachrichtigungsregeln konfiguriert.")}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "700px" }}>
              <thead>
                <tr>
                  <th style={syncTableHeaderStyle}>{t("Name", "Name")}</th>
                  <th style={syncTableHeaderStyle}>{t("Type", "Typ")}</th>
                  <th style={syncTableHeaderStyle}>{t("Details", "Details")}</th>
                  <th style={syncTableHeaderStyle}>{t("Tag", "Tag")}</th>
                  <th style={syncTableHeaderStyle}>{t("Status", "Status")}</th>
                  <th style={syncTableHeaderStyle}>{t("Last Triggered", "Zuletzt ausgelöst")}</th>
                  <th style={syncTableHeaderStyle}>{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {notifRules.map((rule) => (
                  <tr key={rule.id}>
                    <td style={syncTableCellStyle}><strong>{rule.name}</strong></td>
                    <td style={syncTableCellStyle}>
                      <span style={{
                        display: "inline-block",
                        padding: "0.2rem 0.4rem",
                        borderRadius: "0.3rem",
                        fontSize: "0.8rem",
                        background: "rgba(92, 132, 255, 0.1)",
                        color: "#a0b4ff",
                        border: "1px solid rgba(92, 132, 255, 0.2)",
                        whiteSpace: "nowrap",
                      }}>
                        {getRuleTypeLabel(rule.ruleType)}
                      </span>
                    </td>
                    <td style={{ ...syncTableCellStyle, maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      <span style={{ fontSize: "0.85rem", opacity: 0.8 }}>{getRuleDescription(rule)}</span>
                    </td>
                    <td style={syncTableCellStyle}>
                      <code style={{ fontSize: "0.85rem", background: "rgba(255,255,255,0.06)", padding: "0.15rem 0.35rem", borderRadius: "0.25rem" }}>
                        {rule.appriseTag}
                      </code>
                    </td>
                    <td style={syncTableCellStyle}>
                      <span
                        onClick={() => void handleToggleRule(rule)}
                        style={{
                          cursor: "pointer",
                          display: "inline-block",
                          padding: "0.2rem 0.4rem",
                          borderRadius: "0.3rem",
                          fontSize: "0.8rem",
                          fontWeight: 600,
                          whiteSpace: "nowrap",
                          background: rule.enabled ? "rgba(143, 255, 176, 0.13)" : "rgba(136, 136, 136, 0.13)",
                          color: rule.enabled ? "#8fffb0" : "#888",
                          border: `1px solid ${rule.enabled ? "rgba(143, 255, 176, 0.27)" : "rgba(136, 136, 136, 0.27)"}`,
                        }}
                      >
                        {rule.enabled ? t("Active", "Aktiv") : t("Disabled", "Deaktiviert")}
                      </span>
                    </td>
                    <td style={{ ...syncTableCellStyle, whiteSpace: "nowrap" }}>
                      {rule.lastTriggeredAt ? formatDateTime(rule.lastTriggeredAt) : "-"}
                    </td>
                    <td style={syncTableCellStyle}>
                      <div style={{ display: "flex", gap: "0.4rem" }}>
                        <button
                          type="button"
                          onClick={() => openRuleForm(rule)}
                          style={{ fontSize: "0.8rem", minWidth: "60px" }}
                        >
                          {t("Edit", "Bearbeiten")}
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDeleteRule(rule)}
                          disabled={ruleDeletePendingId === rule.id}
                          style={{ fontSize: "0.8rem", minWidth: "60px" }}
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
      </div>

      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Message Templates", "Nachrichtenvorlagen")}</h2>
        <p className="muted">
          {t(
            "Customize notification messages per event type. Use a specific tag to override messages for certain channels, or 'all' for a global default. Templates use {placeholder} variables.",
            "Passe Benachrichtigungstexte pro Ereignistyp an. Verwende einen bestimmten Tag für kanalspezifische Nachrichten oder 'all' als globalen Standard. Vorlagen verwenden {Platzhalter}-Variablen."
          )}
        </p>

        <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" onClick={() => openTemplateForm()} style={{ fontSize: "0.85rem" }}>
            {t("+ Add Template", "+ Vorlage hinzufügen")}
          </button>
        </div>

        {showTemplateForm && (
          <div style={{
            marginTop: "1rem",
            padding: "1rem",
            borderRadius: "0.5rem",
            background: "rgba(255, 255, 255, 0.03)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Event Type", "Ereignistyp")}
                  </label>
                  <select
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
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  >
                    {EVENT_KEY_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                    {t("Tag", "Tag")}
                  </label>
                  <input
                    type="text"
                    value={tplTag}
                    onChange={(e) => setTplTag(e.target.value)}
                    placeholder="all"
                    style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                  />
                  <p className="muted" style={{ margin: "0.25rem 0 0", fontSize: "0.8rem" }}>
                    {t("'all' = global default. Use a channel tag (e.g. email, signal) for channel-specific messages.", "'all' = globaler Standard. Verwende einen Kanal-Tag (z.B. email, signal) für kanalspezifische Nachrichten.")}
                  </p>
                </div>
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  {t("Title Template", "Titel-Vorlage")}
                </label>
                <input
                  type="text"
                  value={tplTitle}
                  onChange={(e) => setTplTitle(e.target.value)}
                  placeholder={DEFAULT_TEMPLATES[tplEventKey].title}
                  style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  {t("Body Template", "Text-Vorlage")}
                </label>
                <textarea
                  value={tplBody}
                  onChange={(e) => setTplBody(e.target.value)}
                  placeholder={DEFAULT_TEMPLATES[tplEventKey].body}
                  rows={tplEventKey === "watch_rule_match" ? 8 : 5}
                  style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box", fontFamily: "inherit", resize: "vertical" }}
                />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                <p className="muted" style={{ margin: 0, fontSize: "0.8rem" }}>
                  {t("Placeholders", "Platzhalter")}: <code style={{ fontSize: "0.8rem", background: "rgba(255,255,255,0.06)", padding: "0.1rem 0.3rem", borderRadius: "0.2rem" }}>{TEMPLATE_PLACEHOLDERS[tplEventKey].scalars}</code>
                </p>
                {TEMPLATE_PLACEHOLDERS[tplEventKey].loop && (
                  <div style={{ margin: 0, fontSize: "0.8rem", opacity: 0.6 }}>
                    <p style={{ margin: "0.2rem 0 0.15rem" }}>
                      {t("Loop block", "Schleifen-Block")} ({t("iterate over each vulnerability", "über jede Schwachstelle iterieren")}):
                    </p>
                    <pre style={{
                      margin: 0,
                      padding: "0.4rem 0.6rem",
                      background: "rgba(255,255,255,0.04)",
                      borderRadius: "0.3rem",
                      fontSize: "0.75rem",
                      lineHeight: 1.5,
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                    }}>
{`{#each vulnerabilities}
{id} — {severity} ({cvss}) — {summary}
{/each}`}
                    </pre>
                    <p style={{ margin: "0.15rem 0 0" }}>
                      {t("Per-vulnerability fields", "Felder pro Schwachstelle")}: <code style={{ fontSize: "0.75rem", background: "rgba(255,255,255,0.06)", padding: "0.1rem 0.3rem", borderRadius: "0.2rem" }}>{"{id}, {severity}, {cvss}, {cwes}, {title}, {summary}, {vendors}, {products}, {versions}, {exploited}, {source}, {published}"}</code>
                    </p>
                  </div>
                )}
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button type="button" onClick={() => void handleSaveTemplate()} disabled={templateSaving || !tplTitle.trim() || !tplBody.trim()} style={{ fontSize: "0.85rem" }}>
                  {templateSaving
                    ? t("Saving...", "Speichern…")
                    : editingTemplate
                      ? t("Update Template", "Vorlage aktualisieren")
                      : t("Create Template", "Vorlage erstellen")}
                </button>
                <button type="button" onClick={() => { setShowTemplateForm(false); resetTemplateForm(); }} style={{ fontSize: "0.85rem" }}>
                  {t("Cancel", "Abbrechen")}
                </button>
              </div>
            </div>
          </div>
        )}

        {templatesLoading ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("Loading templates...", "Lade Vorlagen…")}
          </p>
        ) : templates.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t(
              "No custom message templates configured. Default messages will be used.",
              "Keine benutzerdefinierten Nachrichtenvorlagen konfiguriert. Standardnachrichten werden verwendet."
            )}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "600px" }}>
              <thead>
                <tr>
                  <th style={syncTableHeaderStyle}>{t("Event", "Ereignis")}</th>
                  <th style={syncTableHeaderStyle}>{t("Tag", "Tag")}</th>
                  <th style={syncTableHeaderStyle}>{t("Title", "Titel")}</th>
                  <th style={syncTableHeaderStyle}>{t("Body", "Text")}</th>
                  <th style={syncTableHeaderStyle}>{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {templates.map((tpl) => (
                  <tr key={tpl.id}>
                    <td style={syncTableCellStyle}>
                      <span style={{
                        display: "inline-block",
                        padding: "0.2rem 0.4rem",
                        borderRadius: "0.3rem",
                        fontSize: "0.8rem",
                        background: "rgba(92, 132, 255, 0.1)",
                        color: "#a0b4ff",
                        border: "1px solid rgba(92, 132, 255, 0.2)",
                        whiteSpace: "nowrap",
                      }}>
                        {getEventKeyLabel(tpl.eventKey)}
                      </span>
                    </td>
                    <td style={syncTableCellStyle}>
                      <code style={{ fontSize: "0.85rem", background: "rgba(255,255,255,0.06)", padding: "0.15rem 0.35rem", borderRadius: "0.25rem" }}>
                        {tpl.tag}
                      </code>
                    </td>
                    <td style={{ ...syncTableCellStyle, maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      <span style={{ fontSize: "0.85rem", opacity: 0.8 }}>{tpl.titleTemplate}</span>
                    </td>
                    <td style={{ ...syncTableCellStyle, maxWidth: "250px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      <span style={{ fontSize: "0.85rem", opacity: 0.8 }}>{tpl.bodyTemplate.substring(0, 80)}{tpl.bodyTemplate.length > 80 ? "…" : ""}</span>
                    </td>
                    <td style={syncTableCellStyle}>
                      <div style={{ display: "flex", gap: "0.4rem" }}>
                        <button
                          type="button"
                          onClick={() => openTemplateForm(tpl)}
                          style={{ fontSize: "0.8rem", minWidth: "60px" }}
                        >
                          {t("Edit", "Bearbeiten")}
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDeleteTemplate(tpl)}
                          disabled={templateDeletePendingId === tpl.id}
                          style={{ fontSize: "0.8rem", minWidth: "60px" }}
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
      </div>
      </>)}

      {tab === "data" && (<>
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Sync Status", "Sync-Status")}</h2>
        <p className="muted">
          {t(
            "Overview of all data source synchronizations. Auto-refresh every 5 seconds.",
            "Übersicht über alle Datenquellen-Synchronisationen. Automatische Aktualisierung alle 5 Sekunden."
          )}
        </p>
        {syncLoading ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("Loading sync status ...", "Lade Sync-Status …")}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "900px" }}>
              <thead>
                <tr>
                  <th style={syncTableHeaderStyle}>{t("Sync Job", "Sync-Job")}</th>
                  <th style={syncTableHeaderStyle}>{t("Status", "Status")}</th>
                  <th style={syncTableHeaderStyle}>{t("Started", "Gestartet")}</th>
                  <th style={syncTableHeaderStyle}>{t("Finished", "Beendet")}</th>
                  <th style={syncTableHeaderStyle}>{t("Duration", "Dauer")}</th>
                  <th style={syncTableHeaderStyle}>{t("Next Run", "Nächster Lauf")}</th>
                  <th style={syncTableHeaderStyle}>{t("Actions", "Aktionen")}</th>
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

                  return (
                    <>
                      <tr
                        key={sync.jobName}
                        onClick={() => hasDetails && setExpandedSyncId(isExpanded ? null : sync.jobName)}
                        style={{
                          cursor: hasDetails ? "pointer" : "default",
                          background: isExpanded ? "rgba(255, 255, 255, 0.02)" : undefined,
                        }}
                      >
                        <td style={syncTableCellStyle}>
                          <strong>{sync.label}</strong>
                          {hasDetails && (
                            <span style={{ marginLeft: "0.5rem", fontSize: "0.75rem", opacity: 0.6 }}>
                              {isExpanded ? "▼" : "▶"}
                            </span>
                          )}
                        </td>
                        <td style={syncTableCellStyle}>
                          <span
                            style={{
                              display: "inline-block",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "0.35rem",
                              fontSize: "0.85rem",
                              fontWeight: 600,
                              background: `${getStatusColor(sync.status)}22`,
                              color: getStatusColor(sync.status),
                              border: `1px solid ${getStatusColor(sync.status)}44`,
                            }}
                          >
                            {getStatusLabel(sync.status)}
                          </span>
                        </td>
                        <td style={syncTableCellStyle}>
                          {sync.startedAt ? formatDateTime(sync.startedAt) : "-"}
                        </td>
                        <td style={syncTableCellStyle}>
                          {sync.finishedAt ? formatDateTime(sync.finishedAt) : "-"}
                        </td>
                        <td style={syncTableCellStyle}>{formatDuration(sync.durationSeconds)}</td>
                        <td style={syncTableCellStyle}>
                          {sync.nextRun ? (
                            formatDateTime(sync.nextRun)
                          ) : isInitial ? (
                            <span className="muted" style={{ fontSize: "0.85rem" }}>
                              {t("Only on startup", "Nur bei Start")}
                            </span>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td style={syncTableCellStyle}>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleTriggerSync(syncType, isInitial);
                            }}
                            disabled={isBusy}
                            style={{ minWidth: "120px", fontSize: "0.85rem" }}
                          >
                            {isBusy ? t("Starting...", "Wird gestartet…") : t("Start manually", "Manuell starten")}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && hasDetails && (
                        <tr key={`${sync.jobName}-details`}>
                          <td colSpan={7} style={{ ...syncTableCellStyle, background: "rgba(255, 255, 255, 0.02)", padding: "1rem" }}>
                            {sync.error ? (
                              <div>
                                <strong style={{ color: "#ffa3a3" }}>{t("Error:", "Fehler:")}</strong>
                                <pre style={{ marginTop: "0.5rem", whiteSpace: "pre-wrap", color: "#ffa3a3", fontSize: "0.85rem" }}>
                                  {sync.error}
                                </pre>
                              </div>
                            ) : sync.lastResult ? (
                              <div>
                                <strong>{t("Last result:", "Letztes Ergebnis:")}</strong>
                                <pre style={{ marginTop: "0.5rem", whiteSpace: "pre-wrap", fontSize: "0.85rem", background: "rgba(255, 255, 255, 0.06)", padding: "0.75rem", borderRadius: "0.35rem" }}>
                                  {JSON.stringify(sync.lastResult, null, 2)}
                                </pre>
                              </div>
                            ) : null}
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Vulnerability Re-Sync", "Vulnerability Re-Sync")}</h2>
        <p className="muted">
          {t(
            "Delete vulnerabilities from the database and optionally re-fetch from upstream sources. Supports multiple IDs and wildcard patterns.",
            "Schwachstellen aus der Datenbank löschen und optional von Upstream-Quellen neu abrufen. Mehrere IDs und Wildcards werden unterstützt."
          )}
        </p>
        <div style={{ marginTop: "1rem", maxWidth: "700px" }}>
          <textarea
            value={resyncInput}
            onChange={(e) => setResyncInput(e.target.value)}
            placeholder={t(
              "One ID per line or comma-separated. Wildcards supported (e.g. CVE-2024-*).\nCVE-2026-34043\nGHSA-qj8w-gfj5-8c6v",
              "Eine ID pro Zeile oder kommagetrennt. Wildcards möglich (z.B. CVE-2024-*).\nCVE-2026-34043\nGHSA-qj8w-gfj5-8c6v"
            )}
            disabled={resyncBusy}
            rows={3}
            style={{ width: "100%", minWidth: 0, resize: "vertical", fontFamily: "inherit", fontSize: "0.875rem" }}
          />
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}>
            <button
              type="button"
              onClick={() => void handleResync(false)}
              disabled={resyncBusy || !resyncInput.trim()}
              style={{ whiteSpace: "nowrap" }}
            >
              {resyncBusy ? t("Processing…", "Verarbeitung…") : t("Delete & Re-Sync", "Löschen & Re-Sync")}
            </button>
            <button
              type="button"
              onClick={() => void handleResync(true)}
              disabled={resyncBusy || !resyncInput.trim()}
              style={{ whiteSpace: "nowrap", background: "rgba(255,107,107,0.1)", color: "#ff6b6b", border: "1px solid rgba(255,107,107,0.2)" }}
            >
              {t("Delete Only", "Nur löschen")}
            </button>
          </div>
        </div>
      </div>
      </>)}

      {tab === "general" && (
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Backup & Restore", "Backup & Restore")}</h2>
        <p className="muted">
          {t(
            "Download source backups or restore previously exported backup files.",
            "Lade Sicherungen der Datenquellen herunter oder spiele zuvor exportierte Backups wieder ein."
          )}
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1rem" }}>
          {backupDatasets.map((dataset) => (
            <div
              key={dataset.id}
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "0.75rem",
                padding: "0.75rem",
                borderRadius: "0.5rem",
                background: "rgba(255, 255, 255, 0.02)",
                border: "1px solid rgba(255, 255, 255, 0.06)"
              }}
            >
              <div style={{ flex: "1 1 auto", minWidth: "200px" }}>
                <strong>{dataset.label}</strong>
                <p className="muted" style={{ margin: "0.25rem 0 0" }}>
                  {dataset.description}
                </p>
              </div>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <button type="button" onClick={() => void handleExport(dataset)} disabled={busyId === dataset.id}>
                  {busyId === dataset.id ? t("Please wait...", "Bitte warten…") : t("Download backup", "Backup herunterladen")}
                </button>
                <button type="button" onClick={() => triggerRestoreDialog(dataset.id)} disabled={busyId === dataset.id}>
                  {t("Restore...", "Wiederherstellen…")}
                </button>
                <input
                  type="file"
                  accept="application/json"
                  style={{ display: "none" }}
                  ref={(element) => {
                    fileInputs.current[dataset.id] = element;
                  }}
                  onChange={(event) => handleFileSelection(dataset, event)}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
      )}

      {tab === "policies" && (<>
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("License Policies", "Lizenzrichtlinien")}</h2>
        <p className="muted">
          {t(
            "Define policies to evaluate SBOM component licenses. The default policy is automatically applied after each scan.",
            "Definieren Sie Richtlinien zur Bewertung von SBOM-Komponentenlizenzen. Die Standardrichtlinie wird nach jedem Scan automatisch angewendet."
          )}
        </p>

        <div style={{ marginTop: "1rem" }}>
          {!lpCreating && !lpEditing && (
            <button
              type="button"
              onClick={() => { resetLpForm(); setLpCreating(true); }}
              style={{ marginBottom: "1rem" }}
            >
              + {t("Create Policy", "Richtlinie erstellen")}
            </button>
          )}

          {(lpCreating || lpEditing) && (
            <div style={{
              padding: "1rem", marginBottom: "1rem",
              background: "rgba(255,255,255,0.02)",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: "8px",
            }}>
              <h3 style={{ margin: "0 0 0.75rem", fontSize: "0.9375rem" }}>
                {lpEditing ? t("Edit Policy", "Richtlinie bearbeiten") : t("New Policy", "Neue Richtlinie")}
              </h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: 500, color: "rgba(255,255,255,0.6)", marginBottom: "0.25rem" }}>
                    {t("Name", "Name")}
                  </label>
                  <input type="text" value={lpFormName} onChange={e => setLpFormName(e.target.value)} style={{ width: "100%", maxWidth: "400px" }} />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: 500, color: "rgba(255,255,255,0.6)", marginBottom: "0.25rem" }}>
                    {t("Description", "Beschreibung")}
                  </label>
                  <input type="text" value={lpFormDescription} onChange={e => setLpFormDescription(e.target.value)} style={{ width: "100%", maxWidth: "600px" }} />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: 500, color: "rgba(255,255,255,0.6)", marginBottom: "0.25rem" }}>
                    {t("Allowed Licenses (comma-separated SPDX IDs)", "Erlaubte Lizenzen (kommagetrennte SPDX-IDs)")}
                  </label>
                  <input type="text" value={lpFormAllowed} onChange={e => setLpFormAllowed(e.target.value)} placeholder="MIT, Apache-2.0, BSD-3-Clause, ISC" style={{ width: "100%", maxWidth: "600px" }} />
                  {licenseGroups && (
                    <div style={{ marginTop: "0.375rem", display: "flex", gap: "0.375rem", flexWrap: "wrap" }}>
                      <button type="button" onClick={() => setLpFormAllowed(licenseGroups.permissive.join(", "))}
                        style={{ fontSize: "0.6875rem", padding: "0.125rem 0.5rem", borderRadius: "4px", background: "rgba(99,230,190,0.1)", color: "#63e6be", border: "1px solid rgba(99,230,190,0.2)", cursor: "pointer" }}>
                        {t("Fill: Permissive", "Einfügen: Permissiv")}
                      </button>
                    </div>
                  )}
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: 500, color: "rgba(255,255,255,0.6)", marginBottom: "0.25rem" }}>
                    {t("Denied Licenses (comma-separated SPDX IDs)", "Verbotene Lizenzen (kommagetrennte SPDX-IDs)")}
                  </label>
                  <input type="text" value={lpFormDenied} onChange={e => setLpFormDenied(e.target.value)} placeholder="GPL-3.0-only, AGPL-3.0-only" style={{ width: "100%", maxWidth: "600px" }} />
                  {licenseGroups && (
                    <div style={{ marginTop: "0.375rem", display: "flex", gap: "0.375rem", flexWrap: "wrap" }}>
                      <button type="button" onClick={() => setLpFormDenied(licenseGroups.copyleft.join(", "))}
                        style={{ fontSize: "0.6875rem", padding: "0.125rem 0.5rem", borderRadius: "4px", background: "rgba(255,107,107,0.1)", color: "#ff6b6b", border: "1px solid rgba(255,107,107,0.2)", cursor: "pointer" }}>
                        {t("Fill: Copyleft", "Einfügen: Copyleft")}
                      </button>
                      <button type="button" onClick={() => setLpFormDenied([...licenseGroups.copyleft, ...licenseGroups.weakCopyleft].join(", "))}
                        style={{ fontSize: "0.6875rem", padding: "0.125rem 0.5rem", borderRadius: "4px", background: "rgba(252,196,25,0.1)", color: "#fcc419", border: "1px solid rgba(252,196,25,0.2)", cursor: "pointer" }}>
                        {t("Fill: All Copyleft", "Einfügen: Alle Copyleft")}
                      </button>
                    </div>
                  )}
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: 500, color: "rgba(255,255,255,0.6)", marginBottom: "0.25rem" }}>
                    {t("Default Action (for unlisted licenses)", "Standardaktion (für nicht gelistete Lizenzen)")}
                  </label>
                  <select value={lpFormDefaultAction} onChange={e => setLpFormDefaultAction(e.target.value)}
                    style={{ padding: "0.375rem 0.625rem", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.05)", color: "#fff", fontSize: "0.8125rem" }}>
                    <option value="allow">{t("Allow", "Erlauben")}</option>
                    <option value="warn">{t("Warn", "Warnen")}</option>
                    <option value="deny">{t("Deny", "Verweigern")}</option>
                  </select>
                </div>
                <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.8125rem", color: "rgba(255,255,255,0.7)" }}>
                  <input type="checkbox" checked={lpFormIsDefault} onChange={e => setLpFormIsDefault(e.target.checked)} />
                  {t("Set as default policy", "Als Standardrichtlinie festlegen")}
                </label>
                <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.25rem" }}>
                  <button type="button" onClick={lpEditing ? handleUpdateLicensePolicy : handleCreateLicensePolicy}
                    disabled={!lpFormName.trim()}>
                    {lpEditing ? t("Save", "Speichern") : t("Create", "Erstellen")}
                  </button>
                  <button type="button" onClick={resetLpForm}
                    style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.12)", color: "rgba(255,255,255,0.7)" }}>
                    {t("Cancel", "Abbrechen")}
                  </button>
                </div>
              </div>
            </div>
          )}

          {licensePoliciesLoading ? (
            <p className="muted">{t("Loading...", "Laden...")}</p>
          ) : licensePolicies.length === 0 ? (
            <p className="muted">{t("No license policies configured yet.", "Noch keine Lizenzrichtlinien konfiguriert.")}</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {licensePolicies.map(policy => (
                <div key={policy.id} style={{
                  display: "flex", alignItems: "center", gap: "0.75rem",
                  padding: "0.75rem 1rem",
                  background: "rgba(255,255,255,0.02)",
                  border: `1px solid ${policy.isDefault ? "rgba(99,230,190,0.3)" : "rgba(255,255,255,0.06)"}`,
                  borderRadius: "8px",
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <strong style={{ fontSize: "0.875rem" }}>{policy.name}</strong>
                      {policy.isDefault && (
                        <span style={{
                          padding: "0.0625rem 0.375rem", borderRadius: "4px", fontSize: "0.6875rem", fontWeight: 600,
                          background: "rgba(99,230,190,0.15)", color: "#63e6be",
                        }}>
                          {t("Default", "Standard")}
                        </span>
                      )}
                    </div>
                    {policy.description && (
                      <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", marginTop: "0.125rem" }}>{policy.description}</div>
                    )}
                    <div style={{ fontSize: "0.6875rem", color: "rgba(255,255,255,0.35)", marginTop: "0.25rem" }}>
                      {policy.allowed.length} {t("allowed", "erlaubt")} · {policy.denied.length} {t("denied", "verboten")} · {t("default:", "Standard:")} {policy.defaultAction}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "0.375rem", flexShrink: 0 }}>
                    {!policy.isDefault && (
                      <button type="button" onClick={() => handleSetDefaultPolicy(policy.id)}
                        style={{ fontSize: "0.75rem", padding: "0.25rem 0.5rem", background: "rgba(99,230,190,0.1)", color: "#63e6be", border: "1px solid rgba(99,230,190,0.2)", borderRadius: "4px", cursor: "pointer" }}>
                        {t("Set Default", "Als Standard")}
                      </button>
                    )}
                    <button type="button" onClick={() => startEditingLicensePolicy(policy)}
                      style={{ fontSize: "0.75rem", padding: "0.25rem 0.5rem", background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.6)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "4px", cursor: "pointer" }}>
                      {t("Edit", "Bearbeiten")}
                    </button>
                    <button type="button" onClick={() => handleDeleteLicensePolicy(policy.id)}
                      style={{ fontSize: "0.75rem", padding: "0.25rem 0.5rem", background: "rgba(255,107,107,0.1)", color: "#ff6b6b", border: "1px solid rgba(255,107,107,0.2)", borderRadius: "4px", cursor: "pointer" }}>
                      {t("Delete", "Löschen")}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      </>)}

      {tab === "data" && (
      <div style={subsectionStyle}>
        <h2 style={subsectionHeadingStyle}>{t("Saved Searches", "Gespeicherte Suchen")}</h2>
        <p className="muted">
          {t("Manage saved filters for the vulnerabilities view.", "Verwalte gespeicherte Filter für die Vulnerability-Ansicht.")}{" "}
          {t("Total:", "Gesamt:")} {sortedSavedSearches.length.toLocaleString(locale)}.
        </p>
        {savedSearchLoading && sortedSavedSearches.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("Loading saved searches ...", "Lade gespeicherte Suchen …")}
          </p>
        ) : sortedSavedSearches.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("No saved searches available.", "Es sind keine gespeicherten Suchen vorhanden.")}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "640px" }}>
              <thead>
                <tr>
                  <th style={savedSearchHeaderStyle}>{t("Name", "Name")}</th>
                  <th style={savedSearchHeaderStyle}>{t("Query Params", "Suchparameter")}</th>
                  <th style={savedSearchHeaderStyle}>{t("DQL Query", "DQL Query")}</th>
                  <th style={savedSearchHeaderStyle}>{t("Created", "Erstellt")}</th>
                  <th style={savedSearchHeaderStyle}>{t("Actions", "Aktionen")}</th>
                </tr>
              </thead>
              <tbody>
                {sortedSavedSearches.map((search) => {
                  const isEditing = editingSearchId === search.id;
                  return (
                  <Fragment key={search.id}>
                  <tr>
                    <td style={savedSearchCellStyle}>
                      <strong>{search.name}</strong>
                    </td>
                    <td style={{ ...savedSearchCellStyle, maxWidth: "260px" }}>
                      {search.queryParams ? (
                        <code style={savedSearchCodeStyle}>{search.queryParams}</code>
                      ) : (
                        <span className="muted">-</span>
                      )}
                    </td>
                    <td style={{ ...savedSearchCellStyle, maxWidth: "260px" }}>
                      {search.dqlQuery ? (
                        <code style={savedSearchCodeStyle}>{search.dqlQuery}</code>
                      ) : (
                        <span className="muted">-</span>
                      )}
                    </td>
                    <td style={savedSearchCellStyle}>
                      {formatDateTime(search.createdAt)}
                    </td>
                    <td style={savedSearchCellStyle}>
                      <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button
                          type="button"
                          onClick={() => isEditing ? cancelEditSearch() : startEditSearch(search)}
                          disabled={deletePendingId === search.id}
                          style={{ minWidth: "80px" }}
                        >
                          {isEditing ? t("Cancel", "Abbrechen") : t("Edit", "Bearbeiten")}
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDeleteSavedSearch(search)}
                          disabled={deletePendingId === search.id || isEditing}
                          style={{ minWidth: "80px" }}
                        >
                          {deletePendingId === search.id ? t("Deleting…", "Löschen…") : t("Delete", "Löschen")}
                        </button>
                      </div>
                    </td>
                  </tr>
                  {isEditing && (
                    <tr>
                      <td colSpan={5} style={{ padding: "0 1rem 1rem", borderBottom: "1px solid rgba(255, 255, 255, 0.08)" }}>
                        <div style={{
                          padding: "1rem",
                          borderRadius: "0.5rem",
                          background: "rgba(255, 255, 255, 0.03)",
                          border: "1px solid rgba(255, 255, 255, 0.08)",
                          display: "flex",
                          flexDirection: "column",
                          gap: "0.75rem",
                        }}>
                          <div>
                            <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                              {t("Name", "Name")}
                            </label>
                            <input
                              type="text"
                              value={editName}
                              onChange={(e) => setEditName(e.target.value)}
                              style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                            />
                          </div>
                          {search.dqlQuery ? (
                            <div>
                              <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                                DQL Query
                              </label>
                              <input
                                type="text"
                                value={editDqlQuery}
                                onChange={(e) => setEditDqlQuery(e.target.value)}
                                style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                              />
                            </div>
                          ) : (
                            <div>
                              <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                                {t("Query Params", "Suchparameter")}
                              </label>
                              <input
                                type="text"
                                value={editQueryParams}
                                onChange={(e) => setEditQueryParams(e.target.value)}
                                style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
                              />
                            </div>
                          )}
                          <div style={{ display: "flex", gap: "0.5rem" }}>
                            <button
                              type="button"
                              onClick={() => void handleSaveSearch()}
                              disabled={editSaving || !editName.trim()}
                              style={{ fontSize: "0.85rem" }}
                            >
                              {editSaving ? t("Saving…", "Speichern…") : t("Save", "Speichern")}
                            </button>
                            <button
                              type="button"
                              onClick={cancelEditSearch}
                              disabled={editSaving}
                              style={{ fontSize: "0.85rem" }}
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
      </div>
      )}
      </section>
      {toast && (
        <div style={toastContainerStyle}>
          <div
            role="status"
            aria-live="polite"
            style={{
              ...toastStyle,
              ...(toast.type === "success" ? toastSuccessStyle : toastErrorStyle),
            }}
          >
            {toast.message}
          </div>
        </div>
      )}
    </div>
    )}
  </>
  );
};

const savedSearchHeaderStyle: CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
  fontWeight: 600,
  fontSize: "0.9rem",
};

const savedSearchCellStyle: CSSProperties = {
  padding: "0.65rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
  verticalAlign: "top",
  fontSize: "0.9rem",
};

const savedSearchCodeStyle: CSSProperties = {
  display: "inline-block",
  padding: "0.25rem 0.4rem",
  background: "rgba(255, 255, 255, 0.06)",
  borderRadius: "0.35rem",
  fontSize: "0.85rem",
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
};

const toastContainerStyle: CSSProperties = {
  position: "fixed",
  bottom: "2rem",
  right: "2rem",
  zIndex: 2100,
};

const toastStyle: CSSProperties = {
  background: "rgba(15, 18, 30, 0.92)",
  borderRadius: "10px",
  padding: "0.75rem 1rem",
  color: "#f5f7fa",
  fontWeight: 600,
  boxShadow: "0 18px 40px rgba(0, 0, 0, 0.38)",
  border: "1px solid rgba(255, 255, 255, 0.18)",
  minWidth: "240px",
};

const toastSuccessStyle: CSSProperties = {
  borderColor: "rgba(92, 132, 255, 0.6)",
  color: "#d6e4ff",
};

const toastErrorStyle: CSSProperties = {
  borderColor: "rgba(252, 92, 101, 0.65)",
  color: "#ffb4b6",
};

const subsectionStyle: CSSProperties = {
  marginTop: "2rem",
  paddingTop: "1.5rem",
  borderTop: "1px solid rgba(255, 255, 255, 0.06)",
};

const subsectionHeadingStyle: CSSProperties = {
  marginTop: 0,
};

const syncTableHeaderStyle: CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
  fontWeight: 600,
  fontSize: "0.9rem",
};

const syncTableCellStyle: CSSProperties = {
  padding: "0.65rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
  verticalAlign: "top",
  fontSize: "0.9rem",
};
