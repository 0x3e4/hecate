// Non-React bridge so non-component code (e.g. the axios interceptor) can raise a
// toast. The ToastProvider registers its `showToast`; callers use `emitToast`.
// Mirrors the registerWritePrompt pattern in writeAuth.ts.

export type ToastKind = "success" | "error";
type ToastEmitter = (message: string, type?: ToastKind) => void;

let _emit: ToastEmitter | null = null;

export const registerToast = (fn: ToastEmitter | null): void => {
  _emit = fn;
};

export const emitToast = (message: string, type: ToastKind = "success"): void => {
  _emit?.(message, type);
};
