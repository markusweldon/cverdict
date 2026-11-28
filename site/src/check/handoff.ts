/**
 * A file chosen or dropped on the homepage's Check card, held in this tab's memory for the one
 * navigation to /check, which takes it and checks it like a file dropped there. Nothing is stored
 * or sent: a reload loses it, as it loses a file dropped on the Check page.
 */
let pending: File | null = null;

export const handoff = {
  put(f: File): void {
    pending = f;
  },
  /** The file, once: a second take, or a later visit to /check, gets null. */
  take(): File | null {
    const f = pending;
    pending = null;
    return f;
  },
};
