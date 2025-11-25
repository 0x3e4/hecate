import { formatPublished } from "./dateFormat";

export type PublishedFormat = "date" | "datetime";

export interface PublishedDisplay {
  text: string;
  isReserved: boolean;
}

export const getPublishedDisplay = (
  value?: string | null,
  format: PublishedFormat = "date"
): PublishedDisplay => {
  if (!value) {
    return { text: "", isReserved: true };
  }

  const text = formatPublished(value, format);

  return {
    text,
    isReserved: false,
  };
};
