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

  const date = new Date(value);
  const isValidDate = !Number.isNaN(date.getTime());
  const text = isValidDate
    ? format === "date"
      ? date.toLocaleDateString()
      : date.toLocaleString()
    : value;

  return {
    text,
    isReserved: false,
  };
};
