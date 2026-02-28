/**
 * Application configuration
 */

export const config = {
  /**
   * Timezone for displaying dates and times
   * Default: UTC
   * Examples: Europe/Vienna, America/New_York, Asia/Tokyo
   */
  timezone: import.meta.env.VITE_TIMEZONE || 'UTC',

  /**
   * AI features configuration
   */
  aiFeatures: {
    /**
     * Enable or disable AI analysis features in the UI
     * When false, hides AI-Analyse page and AI tabs
     * Default: true (enabled)
     */
    enabled: import.meta.env.VITE_AI_FEATURES_ENABLED !== 'false',
  },
  /**
   * SCA scanning features configuration
   */
  scaFeatures: {
    /**
     * Enable or disable SCA scanning features in the UI
     * When false, hides SCA-Scans page and nav item
     * Default: true (enabled)
     */
    enabled: import.meta.env.VITE_SCA_FEATURES_ENABLED !== 'false',
    /**
     * Enable or disable the per-target auto-scan toggle in the UI.
     * Should match SCA_AUTO_SCAN_ENABLED on the backend.
     * Default: true (enabled)
     */
    autoScanEnabled: import.meta.env.VITE_SCA_AUTO_SCAN_ENABLED !== 'false',
  },
} as const;
