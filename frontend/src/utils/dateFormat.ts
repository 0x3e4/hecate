/**
 * Centralized date formatting utilities with timezone support
 *
 * All dates from the backend are in UTC (ISO 8601 format with timezone).
 * This utility formats them according to the configured timezone.
 */

import { config } from '../config';
import { getCurrentLanguage, getCurrentLocale } from "../i18n/language";

export type DateFormatStyle = 'short' | 'medium' | 'long' | 'full';

interface DateFormatOptions {
  /** Include time component (default: true for datetime functions, false for date-only) */
  includeTime?: boolean;
  /** Include seconds (default: false) */
  includeSeconds?: boolean;
  /** Date format style (default: 'medium') */
  dateStyle?: DateFormatStyle;
  /** Time format style (default: 'short') */
  timeStyle?: DateFormatStyle;
  /** Override timezone (default: uses config.timezone) */
  timezone?: string;
}

/**
 * Formats a date/datetime string or Date object
 * @param value - ISO string, timestamp, or Date object
 * @param options - Formatting options
 * @returns Formatted date string, or fallback text if invalid
 */
export function formatDate(
  value?: string | number | Date | null,
  options: DateFormatOptions = {}
): string {
  const language = getCurrentLanguage();
  const locale = getCurrentLocale();
  const unknownLabel = language === "de" ? "unbekannt" : "unknown";
  const invalidLabel = language === "de" ? "ungueltig" : "invalid";

  if (!value) {
    return unknownLabel;
  }

  try {
    const date = typeof value === 'string' || typeof value === 'number'
      ? new Date(value)
      : value;

    if (isNaN(date.getTime())) {
      return typeof value === "string" ? value : invalidLabel;
    }

    const {
      includeTime = true,
      includeSeconds = false,
      dateStyle = 'medium',
      timeStyle = 'short',
      timezone = config.timezone,
    } = options;

    if (includeTime) {
      return date.toLocaleString(locale, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        ...(includeSeconds && { second: '2-digit' }),
        timeZone: timezone,
      });
    } else {
      return date.toLocaleDateString(locale, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        timeZone: timezone,
      });
    }
  } catch (error) {
    return typeof value === "string" ? value : invalidLabel;
  }
}

/**
 * Formats a date without time component
 */
export function formatDateOnly(value?: string | number | Date | null): string {
  return formatDate(value, { includeTime: false });
}

/**
 * Formats a datetime with seconds
 */
export function formatDateTime(value?: string | number | Date | null): string {
  return formatDate(value, { includeTime: true, includeSeconds: false });
}

/**
 * Formats a datetime with seconds
 */
export function formatDateTimeWithSeconds(value?: string | number | Date | null): string {
  return formatDate(value, { includeTime: true, includeSeconds: true });
}

/**
 * Legacy compatibility: formats published dates
 * Defaults to date-only format unless explicitly set to datetime
 */
export function formatPublished(
  value?: string | null,
  format: 'date' | 'datetime' = 'date'
): string {
  const unknownLabel = getCurrentLanguage() === "de" ? "unbekannt" : "unknown";
  if (!value) {
    return unknownLabel;
  }
  return formatDate(value, { includeTime: format === 'datetime' });
}
