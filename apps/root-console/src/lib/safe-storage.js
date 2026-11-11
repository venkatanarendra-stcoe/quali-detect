/**
 * localStorage that never throws (private windows, blocked storage, quota). Used only for per-viewer conveniences
 * (theme, last workspace); the app renders correctly without it.
 * @type {import("zustand/middleware").StateStorage}
 */
export const safeStorage = {
  getItem(name) {
    try {
      return window.localStorage.getItem(name);
    } catch {
      return null;
    }
  },
  setItem(name, value) {
    try {
      window.localStorage.setItem(name, value);
    } catch {
      /* ignore: preferences are not persisted */
    }
  },
  removeItem(name) {
    try {
      window.localStorage.removeItem(name);
    } catch {
      /* ignore */
    }
  },
};
