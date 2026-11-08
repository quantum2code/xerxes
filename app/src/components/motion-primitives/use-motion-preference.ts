'use client';

import { useSyncExternalStore } from 'react';
import { useReducedMotion } from 'motion/react';

const subscribe = () => () => {};
const clientSnapshot = () => true;
const serverSnapshot = () => false;

// Match the server tree during hydration, then use Motion's media-query listener.
// All initial animations are disabled, so this does not flash animated content.
export function useMotionPreference() {
  const hydrated = useSyncExternalStore(subscribe, clientSnapshot, serverSnapshot);
  const reducedMotion = useReducedMotion();
  return hydrated && Boolean(reducedMotion);
}
