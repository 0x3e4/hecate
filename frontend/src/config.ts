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
} as const;
