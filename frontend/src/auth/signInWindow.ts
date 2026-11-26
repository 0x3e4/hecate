// Sign-in in a small window, so the page that needed it keeps its state and the
// refused request can run again afterwards (see the access prompt in
// components/WriteAuthProvider.tsx). The window ends on SIGNED_IN_PATH, which
// tells every Hecate tab through a BroadcastChannel and closes itself.

import { loginUrl } from "./returnTo";

export const SIGNED_IN_PATH = "/signed-in";

const CHANNEL = "hecate-auth";
const WINDOW_NAME = "hecate-sign-in";

/**
 * Opens the identity provider in a popup. Returns false when the browser
 * blocked it; call it from a click so it counts as a user gesture.
 */
export const openSignInWindow = (apiBase: string): boolean => {
  if (typeof window === "undefined") return false;
  const width = 520;
  const height = 720;
  const left = Math.max(0, window.screenX + (window.outerWidth - width) / 2);
  const top = Math.max(0, window.screenY + (window.outerHeight - height) / 3);
  const popup = window.open("", WINDOW_NAME, `popup,width=${width},height=${height},left=${left},top=${top}`);
  if (!popup) return false;
  // The identity provider's pages get no handle on this window.
  try {
    popup.opener = null;
  } catch {
    /* some browsers refuse; the IdP is configured by the operator anyway */
  }
  popup.location.href = loginUrl(apiBase, SIGNED_IN_PATH);
  popup.focus();
  return true;
};

/** Called on SIGNED_IN_PATH once the session exists. */
export const announceSignedIn = (): void => {
  try {
    const channel = new BroadcastChannel(CHANNEL);
    channel.postMessage({ type: "signed-in" });
    channel.close();
  } catch {
    /* no BroadcastChannel: the waiting page also checks when it regains focus */
  }
};

/** Runs `callback` when another Hecate window finished a sign-in. */
export const onSignedInElsewhere = (callback: () => void): (() => void) => {
  let channel: BroadcastChannel | null = null;
  try {
    channel = new BroadcastChannel(CHANNEL);
    channel.onmessage = (event: MessageEvent) => {
      if ((event.data as { type?: string } | null)?.type === "signed-in") callback();
    };
  } catch {
    return () => undefined;
  }
  return () => channel?.close();
};
