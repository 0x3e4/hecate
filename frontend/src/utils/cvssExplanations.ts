/**
 * Explanations for CVSS metric values across versions 2.0, 3.x, and 4.0.
 *
 * Keys match the attribute labels used in CvssMetricDisplay.
 * Value keys are the UPPERCASE display values produced by formatEnumValue().
 */
import { AppLanguage, getCurrentLanguage } from "../i18n/language";

export interface CvssValueExplanation {
  /** Description of what the metric measures */
  metric: string;
  /** Map of normalized display value -> explanation */
  values: Record<string, string>;
}

type ExplanationMap = Record<string, CvssValueExplanation>;

const CVSS_EXPLANATIONS_DE: ExplanationMap = {
  // -- Common across versions ------------------------------------------

  "Attack Vector": {
    metric: "Beschreibt, wie ein Angreifer Zugriff auf das verwundbare System erlangen kann.",
    values: {
      NETWORK:
        "Der Angriff kann über das Netzwerk erfolgen, z.\u00a0B. aus dem Internet. Der Angreifer muss keinen physischen oder lokalen Zugang haben.",
      ADJACENT:
        "Der Angriff ist auf ein logisch benachbartes Netzwerk beschränkt, z.\u00a0B. Bluetooth, NFC oder dasselbe lokale Subnetz.",
      "ADJACENT NETWORK":
        "Der Angriff ist auf ein logisch benachbartes Netzwerk beschränkt, z.\u00a0B. dasselbe lokale Subnetz.",
      LOCAL:
        "Der Angreifer benötigt lokalen Zugang zum System, z.\u00a0B. über eine Terminal-Sitzung, oder der Angriff erfordert eine Benutzerinteraktion (z.\u00a0B. Öffnen einer Datei).",
      PHYSICAL:
        "Der Angreifer muss das verwundbare System physisch berühren oder manipulieren können.",
    },
  },

  "Attack Complexity": {
    metric: "Beschreibt die Bedingungen, die außerhalb der Kontrolle des Angreifers liegen und für einen erfolgreichen Angriff gegeben sein müssen.",
    values: {
      LOW: "Es sind keine besonderen Voraussetzungen nötig. Der Angriff ist wiederholbar und zuverlässig durchführbar.",
      MEDIUM:
        "Der Angriff erfordert bestimmte Umstände oder Informationen, die nicht immer gegeben sind.",
      HIGH: "Der Angriff erfordert das Umgehen von Schutzmechanismen (z.\u00a0B. ASLR, DEP) oder das Kennen systemspezifischer Geheimnisse. Der Erfolg ist nicht garantiert.",
    },
  },

  // -- CVSS 4.0 --------------------------------------------------------

  "Attack Requirements": {
    metric: "Beschreibt, ob der Angriff von bestimmten Bereitstellungs- oder Ausführungsbedingungen des Zielsystems abhängt (CVSS 4.0).",
    values: {
      NONE: "Der Angriff ist unabhängig von der Konfiguration oder Umgebung des Zielsystems erfolgreich.",
      PRESENT:
        "Der Erfolg hängt von bestimmten Bedingungen ab, z.\u00a0B. einer Race-Condition, einer bestimmten Netzwerkkonfiguration oder der Notwendigkeit einer Man-in-the-Middle-Position.",
    },
  },

  // -- CVSS 3.x / 4.0 -------------------------------------------------

  "Privileges Required": {
    metric: "Beschreibt, welche Berechtigungsstufe ein Angreifer vor dem Angriff benötigt.",
    values: {
      NONE: "Der Angreifer benötigt keinerlei Authentifizierung oder Zugriffsrechte.",
      LOW: "Der Angreifer benötigt Basisrechte, die typischerweise einem normalen Benutzer entsprechen.",
      HIGH: "Der Angreifer benötigt administrative oder weitreichende Systemberechtigungen.",
    },
  },

  "User Interaction": {
    metric: "Beschreibt, ob ein Benutzer (außer dem Angreifer) aktiv an dem Angriff mitwirken muss.",
    values: {
      NONE: "Der Angriff erfordert keine Mitwirkung eines Benutzers.",
      REQUIRED:
        "Ein Benutzer muss eine Aktion ausführen, bevor die Schwachstelle ausgenutzt werden kann (z.\u00a0B. einen Link anklicken oder eine Datei öffnen).",
      PASSIVE:
        "Der Angriff erfordert eine eingeschränkte, unfreiwillige Benutzerinteraktion, z.\u00a0B. den Besuch einer manipulierten Webseite (CVSS 4.0).",
      ACTIVE:
        "Der Angriff erfordert eine bewusste, gezielte Benutzerinteraktion, z.\u00a0B. das Importieren einer Datei oder das Absenden eines Formulars (CVSS 4.0).",
    },
  },

  // -- CVSS 3.x --------------------------------------------------------

  Scope: {
    metric: "Beschreibt, ob die Auswirkung über das verwundbare System hinaus auf andere Systeme übergreift (CVSS 3.x).",
    values: {
      UNCHANGED:
        "Die Auswirkungen beschränken sich auf das verwundbare System selbst.",
      CHANGED:
        "Die Auswirkungen gehen über das verwundbare System hinaus und können weitere Komponenten oder Systeme betreffen.",
    },
  },

  // -- CVSS 2.0 --------------------------------------------------------

  Authentication: {
    metric: "Gibt an, wie oft sich ein Angreifer authentifizieren muss, um die Schwachstelle auszunutzen (CVSS 2.0).",
    values: {
      NONE: "Der Angreifer muss sich nicht authentifizieren.",
      SINGLE:
        "Der Angreifer muss sich einmal authentifizieren, um den Angriff durchzuführen.",
      MULTIPLE:
        "Der Angreifer muss sich mehrfach authentifizieren, um den Angriff durchzuführen.",
    },
  },

  // -- Impact: CVSS 2.0 (None/Partial/Complete), 3.x (None/Low/High) --

  "Confidentiality Impact": {
    metric: "Beschreibt das Ausmaß des Verlusts an Vertraulichkeit.",
    values: {
      NONE: "Kein Verlust der Vertraulichkeit.",
      PARTIAL:
        "Zugriff auf einige geschützte Informationen, aber der Angreifer hat keine volle Kontrolle über den Umfang (CVSS 2.0).",
      COMPLETE:
        "Vollständiger Verlust der Vertraulichkeit - alle Informationen auf dem System werden offengelegt (CVSS 2.0).",
      LOW: "Zugriff auf einige eingeschränkte Informationen, jedoch ohne schwerwiegenden direkten Schaden.",
      HIGH: "Vollständiger Verlust der Vertraulichkeit - alle Daten des Systems können offengelegt werden.",
    },
  },

  "Integrity Impact": {
    metric: "Beschreibt das Ausmaß der Beeinträchtigung der Datenintegrität.",
    values: {
      NONE: "Keine Beeinträchtigung der Integrität.",
      PARTIAL:
        "Daten können teilweise verändert werden, aber der Angreifer kontrolliert nicht den gesamten Umfang (CVSS 2.0).",
      COMPLETE:
        "Vollständiger Verlust der Integrität - der Angreifer kann beliebige Daten auf dem System verändern (CVSS 2.0).",
      LOW: "Daten können eingeschränkt verändert werden, ohne schwerwiegende direkte Folgen.",
      HIGH: "Vollständiger Verlust der Integrität - der Angreifer kann beliebige Daten verändern.",
    },
  },

  "Availability Impact": {
    metric: "Beschreibt das Ausmaß der Beeinträchtigung der Verfügbarkeit.",
    values: {
      NONE: "Keine Beeinträchtigung der Verfügbarkeit.",
      PARTIAL:
        "Die Leistung wird reduziert oder Unterbrechungen treten auf, aber der Dienst ist nicht vollständig blockiert (CVSS 2.0).",
      COMPLETE:
        "Vollständiger Verlust der Verfügbarkeit - der Angreifer kann den Zugriff vollständig unterbinden (CVSS 2.0).",
      LOW: "Die Leistung wird reduziert oder es kommt zu Unterbrechungen, aber der Dienst bleibt grundsätzlich erreichbar.",
      HIGH: "Vollständiger Verlust der Verfügbarkeit - der Zugriff auf das System kann vollständig blockiert werden.",
    },
  },

  // -- CVSS 4.0: Vulnerable System impacts -----------------------------

  "Vuln. Confidentiality": {
    metric: "Beschreibt den Vertraulichkeitsverlust im direkt verwundbaren System (CVSS 4.0).",
    values: {
      NONE: "Kein Vertraulichkeitsverlust im verwundbaren System.",
      LOW: "Eingeschränkter Zugriff auf geschützte Informationen des verwundbaren Systems, ohne schwerwiegenden direkten Schaden.",
      HIGH: "Vollständiger Verlust der Vertraulichkeit - alle Informationen des verwundbaren Systems können offengelegt werden.",
    },
  },

  "Vuln. Integrity": {
    metric: "Beschreibt die Integritätsbeeinträchtigung im direkt verwundbaren System (CVSS 4.0).",
    values: {
      NONE: "Keine Integritätsbeeinträchtigung im verwundbaren System.",
      LOW: "Eingeschränkte Veränderungsmöglichkeit von Daten im verwundbaren System.",
      HIGH: "Vollständiger Verlust der Integrität - beliebige Daten des verwundbaren Systems können verändert werden.",
    },
  },

  "Vuln. Availability": {
    metric: "Beschreibt die Verfügbarkeitsbeeinträchtigung im direkt verwundbaren System (CVSS 4.0).",
    values: {
      NONE: "Keine Verfügbarkeitsbeeinträchtigung im verwundbaren System.",
      LOW: "Die Leistung des verwundbaren Systems wird reduziert oder es treten Unterbrechungen auf.",
      HIGH: "Vollständiger Verlust der Verfügbarkeit - der Zugriff auf das verwundbare System kann vollständig blockiert werden.",
    },
  },

  // -- CVSS 4.0: Subsequent System impacts -----------------------------

  "Sub. Confidentiality": {
    metric: "Beschreibt den Vertraulichkeitsverlust in nachgelagerten Systemen, die nicht direkt verwundbar sind (CVSS 4.0).",
    values: {
      NONE: "Kein Vertraulichkeitsverlust in nachgelagerten Systemen.",
      LOW: "Eingeschränkter Zugriff auf geschützte Informationen nachgelagerter Systeme.",
      HIGH: "Vollständiger Verlust der Vertraulichkeit in nachgelagerten Systemen - offengelegte Informationen haben schwerwiegende Auswirkungen.",
    },
  },

  "Sub. Integrity": {
    metric: "Beschreibt die Integritätsbeeinträchtigung in nachgelagerten Systemen (CVSS 4.0).",
    values: {
      NONE: "Keine Integritätsbeeinträchtigung in nachgelagerten Systemen.",
      LOW: "Eingeschränkte Veränderungsmöglichkeit von Daten in nachgelagerten Systemen.",
      HIGH: "Vollständiger Verlust der Integrität in nachgelagerten Systemen - beliebige Daten können verändert werden.",
    },
  },

  "Sub. Availability": {
    metric: "Beschreibt die Verfügbarkeitsbeeinträchtigung in nachgelagerten Systemen (CVSS 4.0).",
    values: {
      NONE: "Keine Verfügbarkeitsbeeinträchtigung in nachgelagerten Systemen.",
      LOW: "Die Leistung nachgelagerter Systeme wird reduziert oder es treten Unterbrechungen auf.",
      HIGH: "Vollständiger Verlust der Verfügbarkeit in nachgelagerten Systemen.",
    },
  },

  // -- CVSS 4.0: Threat Metrics ----------------------------------------

  "Exploit Maturity": {
    metric: "Beschreibt den aktuellen Stand der Ausnutzungstechniken oder der Verfügbarkeit von Exploit-Code (CVSS 4.0).",
    values: {
      ATTACKED:
        "Es wurden bereits Angriffe auf diese Schwachstelle beobachtet, oder es existieren öffentlich verfügbare Exploit-Tools.",
      "PROOF OF CONCEPT":
        "Es existiert ein öffentlich verfügbarer Proof-of-Concept-Exploit, aber es wurden keine aktiven Angriffe gemeldet.",
      UNREPORTED:
        "Es sind weder öffentliche Exploits noch Angriffsberichte bekannt.",
    },
  },

  // -- CVSS 4.0: Supplemental Metrics ----------------------------------

  Safety: {
    metric: "Gibt an, ob die Ausnutzung der Schwachstelle Auswirkungen auf die Sicherheit von Personen haben kann (IEC 61508).",
    values: {
      PRESENT:
        'Die Folgen können zu Verletzungen führen, die gemäß IEC 61508 als "marginal", "kritisch" oder "katastrophal" eingestuft werden.',
      NEGLIGIBLE:
        'Die Folgen sind gemäß IEC 61508 als "vernachlässigbar" einzustufen - höchstens leichte Verletzungen.',
    },
  },

  Automatable: {
    metric: "Gibt an, ob ein Angreifer alle vier Schritte der Kill-Chain (Aufklärung, Bewaffnung, Zustellung, Ausnutzung) zuverlässig automatisieren kann.",
    values: {
      NO: "Die Kill-Chain kann nicht vollständig automatisiert werden - manuelle Schritte sind erforderlich.",
      YES: "Alle vier Schritte der Kill-Chain können zuverlässig automatisiert werden, was die Skalierbarkeit des Angriffs erhöht.",
    },
  },

  Recovery: {
    metric: "Beschreibt die Fähigkeit des Systems, sich nach einem Angriff zu erholen.",
    values: {
      AUTOMATIC:
        "Das System stellt seine Dienste nach dem Angriff automatisch wieder her.",
      USER: "Die Wiederherstellung erfordert manuelle Eingriffe durch einen Administrator.",
      IRRECOVERABLE:
        "Die Dienste des Systems können nach dem Angriff nicht wiederhergestellt werden.",
    },
  },

  "Value Density": {
    metric: "Beschreibt die Ressourcendichte des verwundbaren Systems.",
    values: {
      DIFFUSE:
        "Das System hat begrenzte Ressourcen. Der Ertrag für den Angreifer ist relativ gering.",
      CONCENTRATED:
        "Das System ist ressourcenreich (z.\u00a0B. ein Server). Ein erfolgreicher Angriff kann einen hohen Ertrag bringen.",
    },
  },

  "Response Effort": {
    metric: "Beschreibt den Aufwand, der für die Behebung der Schwachstelle erforderlich ist.",
    values: {
      LOW: "Geringer Aufwand - z.\u00a0B. Dokumentation, Workarounds oder einfache Konfigurationsänderungen genügen.",
      MODERATE:
        "Mittlerer Aufwand - z.\u00a0B. ein einfaches Update oder eine Treiberinstallation mit minimaler Dienstunterbrechung.",
      HIGH: "Erheblicher Aufwand - z.\u00a0B. ein privilegiertes Update, BIOS-Aktualisierung oder Hardwareaustausch mit möglicher längerer Ausfallzeit.",
    },
  },

  "Provider Urgency": {
    metric: "Vom Hersteller oder Anbieter festgelegte Dringlichkeitsbewertung.",
    values: {
      RED: "Höchste Dringlichkeit - sofortiges Handeln empfohlen.",
      AMBER: "Mittlere Dringlichkeit - zeitnahe Maßnahmen empfohlen.",
      GREEN: "Niedrige Dringlichkeit - Maßnahmen sind planbar.",
      CLEAR: "Informativ - kein unmittelbarer Handlungsbedarf.",
    },
  },

  // -- CVSS 4.0: Environmental Requirements ----------------------------

  "Confidentiality Requirement": {
    metric: "Gibt die Bedeutung der Vertraulichkeit für das betroffene System an.",
    values: {
      LOW: "Ein Verlust der Vertraulichkeit hätte nur eingeschränkte Auswirkungen.",
      MEDIUM: "Ein Verlust der Vertraulichkeit hätte schwerwiegende Auswirkungen.",
      HIGH: "Ein Verlust der Vertraulichkeit hätte katastrophale Auswirkungen.",
    },
  },

  "Integrity Requirement": {
    metric: "Gibt die Bedeutung der Integrität für das betroffene System an.",
    values: {
      LOW: "Ein Verlust der Integrität hätte nur eingeschränkte Auswirkungen.",
      MEDIUM: "Ein Verlust der Integrität hätte schwerwiegende Auswirkungen.",
      HIGH: "Ein Verlust der Integrität hätte katastrophale Auswirkungen.",
    },
  },

  "Availability Requirement": {
    metric: "Gibt die Bedeutung der Verfügbarkeit für das betroffene System an.",
    values: {
      LOW: "Ein Verlust der Verfügbarkeit hätte nur eingeschränkte Auswirkungen.",
      MEDIUM: "Ein Verlust der Verfügbarkeit hätte schwerwiegende Auswirkungen.",
      HIGH: "Ein Verlust der Verfügbarkeit hätte katastrophale Auswirkungen.",
    },
  },
};

const CVSS_EXPLANATIONS_EN: ExplanationMap = {
  // -- Common across versions ------------------------------------------

  "Attack Vector": {
    metric: "Describes how an attacker can gain access to the vulnerable system.",
    values: {
      NETWORK:
        "The attack can be carried out over the network, e.g. from the Internet. The attacker does not need physical or local access.",
      ADJACENT:
        "The attack is limited to a logically adjacent network, e.g. Bluetooth, NFC, or the same local subnet.",
      "ADJACENT NETWORK":
        "The attack is limited to a logically adjacent network, e.g. the same local subnet.",
      LOCAL:
        "The attacker needs local access to the system, e.g. via a terminal session, or the attack requires user interaction (e.g. opening a file).",
      PHYSICAL:
        "The attacker must be able to physically touch or manipulate the vulnerable system.",
    },
  },

  "Attack Complexity": {
    metric: "Describes conditions beyond the attacker's control that must exist for a successful attack.",
    values: {
      LOW: "No special prerequisites are needed. The attack is repeatable and reliably executable.",
      MEDIUM:
        "The attack requires specific circumstances or information that are not always present.",
      HIGH: "The attack requires bypassing security mechanisms (e.g. ASLR, DEP) or knowledge of system-specific secrets. Success is not guaranteed.",
    },
  },

  // -- CVSS 4.0 --------------------------------------------------------

  "Attack Requirements": {
    metric: "Describes whether the attack depends on specific deployment or execution conditions of the target system (CVSS 4.0).",
    values: {
      NONE: "The attack succeeds regardless of the target system's configuration or environment.",
      PRESENT:
        "Success depends on specific conditions, e.g. a race condition, a particular network configuration, or the need for a man-in-the-middle position.",
    },
  },

  // -- CVSS 3.x / 4.0 -------------------------------------------------

  "Privileges Required": {
    metric: "Describes what level of privileges an attacker needs before the attack.",
    values: {
      NONE: "The attacker requires no authentication or access rights.",
      LOW: "The attacker needs basic privileges typically corresponding to a normal user.",
      HIGH: "The attacker needs administrative or extensive system privileges.",
    },
  },

  "User Interaction": {
    metric: "Describes whether a user (other than the attacker) must actively participate in the attack.",
    values: {
      NONE: "The attack requires no user participation.",
      REQUIRED:
        "A user must perform an action before the vulnerability can be exploited (e.g. clicking a link or opening a file).",
      PASSIVE:
        "The attack requires limited, involuntary user interaction, e.g. visiting a manipulated website (CVSS 4.0).",
      ACTIVE:
        "The attack requires deliberate, targeted user interaction, e.g. importing a file or submitting a form (CVSS 4.0).",
    },
  },

  // -- CVSS 3.x --------------------------------------------------------

  Scope: {
    metric: "Describes whether the impact extends beyond the vulnerable system to other systems (CVSS 3.x).",
    values: {
      UNCHANGED:
        "The impact is limited to the vulnerable system itself.",
      CHANGED:
        "The impact extends beyond the vulnerable system and can affect other components or systems.",
    },
  },

  // -- CVSS 2.0 --------------------------------------------------------

  Authentication: {
    metric: "Indicates how many times an attacker must authenticate to exploit the vulnerability (CVSS 2.0).",
    values: {
      NONE: "The attacker does not need to authenticate.",
      SINGLE:
        "The attacker must authenticate once to carry out the attack.",
      MULTIPLE:
        "The attacker must authenticate multiple times to carry out the attack.",
    },
  },

  // -- Impact: CVSS 2.0 (None/Partial/Complete), 3.x (None/Low/High) --

  "Confidentiality Impact": {
    metric: "Describes the extent of confidentiality loss.",
    values: {
      NONE: "No loss of confidentiality.",
      PARTIAL:
        "Access to some protected information, but the attacker does not have full control over the scope (CVSS 2.0).",
      COMPLETE:
        "Complete loss of confidentiality - all information on the system is disclosed (CVSS 2.0).",
      LOW: "Access to some restricted information, but without serious direct damage.",
      HIGH: "Complete loss of confidentiality - all system data can be disclosed.",
    },
  },

  "Integrity Impact": {
    metric: "Describes the extent of data integrity compromise.",
    values: {
      NONE: "No integrity compromise.",
      PARTIAL:
        "Data can be partially modified, but the attacker does not control the full scope (CVSS 2.0).",
      COMPLETE:
        "Complete loss of integrity - the attacker can modify any data on the system (CVSS 2.0).",
      LOW: "Data can be modified in a limited way, without serious direct consequences.",
      HIGH: "Complete loss of integrity - the attacker can modify any data.",
    },
  },

  "Availability Impact": {
    metric: "Describes the extent of availability impact.",
    values: {
      NONE: "No availability impact.",
      PARTIAL:
        "Performance is reduced or interruptions occur, but the service is not completely blocked (CVSS 2.0).",
      COMPLETE:
        "Complete loss of availability - the attacker can completely block access (CVSS 2.0).",
      LOW: "Performance is reduced or interruptions occur, but the service remains generally accessible.",
      HIGH: "Complete loss of availability - access to the system can be completely blocked.",
    },
  },

  // -- CVSS 4.0: Vulnerable System impacts -----------------------------

  "Vuln. Confidentiality": {
    metric: "Describes the confidentiality loss in the directly vulnerable system (CVSS 4.0).",
    values: {
      NONE: "No confidentiality loss in the vulnerable system.",
      LOW: "Limited access to protected information of the vulnerable system, without serious direct damage.",
      HIGH: "Complete loss of confidentiality - all information of the vulnerable system can be disclosed.",
    },
  },

  "Vuln. Integrity": {
    metric: "Describes the integrity impact on the directly vulnerable system (CVSS 4.0).",
    values: {
      NONE: "No integrity impact on the vulnerable system.",
      LOW: "Limited ability to modify data in the vulnerable system.",
      HIGH: "Complete loss of integrity - any data of the vulnerable system can be modified.",
    },
  },

  "Vuln. Availability": {
    metric: "Describes the availability impact on the directly vulnerable system (CVSS 4.0).",
    values: {
      NONE: "No availability impact on the vulnerable system.",
      LOW: "Performance of the vulnerable system is reduced or interruptions occur.",
      HIGH: "Complete loss of availability - access to the vulnerable system can be completely blocked.",
    },
  },

  // -- CVSS 4.0: Subsequent System impacts -----------------------------

  "Sub. Confidentiality": {
    metric: "Describes the confidentiality loss in subsequent systems that are not directly vulnerable (CVSS 4.0).",
    values: {
      NONE: "No confidentiality loss in subsequent systems.",
      LOW: "Limited access to protected information of subsequent systems.",
      HIGH: "Complete loss of confidentiality in subsequent systems - disclosed information has severe impact.",
    },
  },

  "Sub. Integrity": {
    metric: "Describes the integrity impact on subsequent systems (CVSS 4.0).",
    values: {
      NONE: "No integrity impact on subsequent systems.",
      LOW: "Limited ability to modify data in subsequent systems.",
      HIGH: "Complete loss of integrity in subsequent systems - any data can be modified.",
    },
  },

  "Sub. Availability": {
    metric: "Describes the availability impact on subsequent systems (CVSS 4.0).",
    values: {
      NONE: "No availability impact on subsequent systems.",
      LOW: "Performance of subsequent systems is reduced or interruptions occur.",
      HIGH: "Complete loss of availability in subsequent systems.",
    },
  },

  // -- CVSS 4.0: Threat Metrics ----------------------------------------

  "Exploit Maturity": {
    metric: "Describes the current state of exploitation techniques or availability of exploit code (CVSS 4.0).",
    values: {
      ATTACKED:
        "Attacks on this vulnerability have already been observed, or publicly available exploit tools exist.",
      "PROOF OF CONCEPT":
        "A publicly available proof-of-concept exploit exists, but no active attacks have been reported.",
      UNREPORTED:
        "No public exploits or attack reports are known.",
    },
  },

  // -- CVSS 4.0: Supplemental Metrics ----------------------------------

  Safety: {
    metric: "Indicates whether exploitation of the vulnerability can impact the safety of people (IEC 61508).",
    values: {
      PRESENT:
        'The consequences can lead to injuries classified as "marginal", "critical", or "catastrophic" according to IEC 61508.',
      NEGLIGIBLE:
        'The consequences are classified as "negligible" according to IEC 61508 - at most minor injuries.',
    },
  },

  Automatable: {
    metric: "Indicates whether an attacker can reliably automate all four steps of the kill chain (reconnaissance, weaponization, delivery, exploitation).",
    values: {
      NO: "The kill chain cannot be fully automated - manual steps are required.",
      YES: "All four steps of the kill chain can be reliably automated, increasing the scalability of the attack.",
    },
  },

  Recovery: {
    metric: "Describes the system's ability to recover after an attack.",
    values: {
      AUTOMATIC:
        "The system automatically restores its services after the attack.",
      USER: "Recovery requires manual intervention by an administrator.",
      IRRECOVERABLE:
        "The system's services cannot be restored after the attack.",
    },
  },

  "Value Density": {
    metric: "Describes the resource density of the vulnerable system.",
    values: {
      DIFFUSE:
        "The system has limited resources. The yield for the attacker is relatively low.",
      CONCENTRATED:
        "The system is resource-rich (e.g. a server). A successful attack can yield high returns.",
    },
  },

  "Response Effort": {
    metric: "Describes the effort required to remediate the vulnerability.",
    values: {
      LOW: "Low effort - e.g. documentation, workarounds, or simple configuration changes suffice.",
      MODERATE:
        "Moderate effort - e.g. a simple update or driver installation with minimal service disruption.",
      HIGH: "Significant effort - e.g. a privileged update, BIOS update, or hardware replacement with potential extended downtime.",
    },
  },

  "Provider Urgency": {
    metric: "Urgency rating set by the vendor or provider.",
    values: {
      RED: "Highest urgency - immediate action recommended.",
      AMBER: "Medium urgency - timely action recommended.",
      GREEN: "Low urgency - action can be planned.",
      CLEAR: "Informational - no immediate action required.",
    },
  },

  // -- CVSS 4.0: Environmental Requirements ----------------------------

  "Confidentiality Requirement": {
    metric: "Indicates the importance of confidentiality for the affected system.",
    values: {
      LOW: "A loss of confidentiality would have only limited impact.",
      MEDIUM: "A loss of confidentiality would have serious impact.",
      HIGH: "A loss of confidentiality would have catastrophic impact.",
    },
  },

  "Integrity Requirement": {
    metric: "Indicates the importance of integrity for the affected system.",
    values: {
      LOW: "A loss of integrity would have only limited impact.",
      MEDIUM: "A loss of integrity would have serious impact.",
      HIGH: "A loss of integrity would have catastrophic impact.",
    },
  },

  "Availability Requirement": {
    metric: "Indicates the importance of availability for the affected system.",
    values: {
      LOW: "A loss of availability would have only limited impact.",
      MEDIUM: "A loss of availability would have serious impact.",
      HIGH: "A loss of availability would have catastrophic impact.",
    },
  },
};

const EXPLANATIONS_BY_LANG: Record<AppLanguage, ExplanationMap> = {
  de: CVSS_EXPLANATIONS_DE,
  en: CVSS_EXPLANATIONS_EN,
};

const MODIFIED_PREFIX = "Modified ";

/**
 * Try multiple label variations to find a match in the explanations map.
 * Handles "Modified ..." prefixes and period/no-period differences
 * (e.g. "Modified Vuln Confidentiality" -> "Vuln. Confidentiality").
 */
const resolveEntry = (label: string, map: ExplanationMap): CvssValueExplanation | undefined => {
  const direct = map[label];
  if (direct) return direct;

  // Strip "Modified " prefix
  let base = label;
  if (base.startsWith(MODIFIED_PREFIX)) {
    base = base.slice(MODIFIED_PREFIX.length);
    const fromBase = map[base];
    if (fromBase) return fromBase;
  }

  // Try adding period after "Vuln" / "Sub" (label uses "Vuln " but map key uses "Vuln. ")
  const withPeriod = base.replace(/^(Vuln|Sub)\s/, "$1. ");
  if (withPeriod !== base) {
    const fromPeriod = map[withPeriod];
    if (fromPeriod) return fromPeriod;
  }

  return undefined;
};

/**
 * Look up the explanation for a CVSS metric label + display value.
 * Falls back to the base metric for "Modified ..." labels.
 */
export const getCvssExplanation = (
  label: string,
  displayValue: string
): { metric: string; value: string | null } | null => {
  const lang = getCurrentLanguage();
  const map = EXPLANATIONS_BY_LANG[lang];
  const entry = resolveEntry(label, map);
  if (!entry) {
    return null;
  }
  const normalized = displayValue.toUpperCase().replace(/_/g, " ").replace(/\s+/g, " ").trim();
  return {
    metric: entry.metric,
    value: entry.values[normalized] ?? null,
  };
};
