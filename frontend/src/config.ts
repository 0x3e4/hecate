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
} as const;
