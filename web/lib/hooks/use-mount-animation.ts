"use client";

import { useEffect, useState, useSyncExternalStore } from "react";

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function subscribeReducedMotion(onChange: () => void): () => void {
  if (typeof window === "undefined" || !window.matchMedia) {
    return () => undefined;
  }
  const media = window.matchMedia(REDUCED_MOTION_QUERY);
  media.addEventListener("change", onChange);
  return () => media.removeEventListener("change", onChange);
}

function getReducedMotionSnapshot(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

function getReducedMotionServerSnapshot(): boolean {
  return false;
}

/**
 * Reads `prefers-reduced-motion: reduce` and stays in sync if the user
 * toggles the preference mid-session. SSR-safe: returns `false` on the
 * server so the server and client agree on the first paint.
 *
 * Implemented with `useSyncExternalStore` (the React 19 pattern for
 * subscribing to an external store) rather than useEffect + useState, so
 * the strict `react-hooks/set-state-in-effect` rule stays satisfied.
 */
export function usePrefersReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribeReducedMotion,
    getReducedMotionSnapshot,
    getReducedMotionServerSnapshot,
  );
}

/**
 * Gate a mount-time animation. Returns `true` after `delay` ms on the
 * client, or immediately if the user prefers reduced motion (so the
 * component jumps straight to its final state with no transition).
 *
 * Used by ScoreRing, ContributionBar, and any component whose first render
 * should play a one-time entrance animation.
 *
 * Implementation notes:
 *  - The reduced-motion branch is computed as derived state
 *    (`reduced || timerMounted`) instead of calling setState in the
 *    effect body, which React 19 lints against.
 *  - For zero-delay mounts we schedule via a double `requestAnimationFrame`
 *    instead of `setTimeout(0)`. The double rAF guarantees the browser
 *    has committed the initial style frame before we flip to the target
 *    state, so the CSS transition actually has two distinct values to
 *    interpolate between. Without it React batches both frames into one
 *    paint and the animation gets skipped.
 *  - For non-zero delays we still use a timer, since the intent is to
 *    intentionally wait.
 */
export function useMountAnimation(delay: number = 0): boolean {
  const reduced = usePrefersReducedMotion();
  const [timerMounted, setTimerMounted] = useState(false);

  useEffect(() => {
    if (reduced) return undefined;
    if (timerMounted) return undefined;

    if (delay <= 0) {
      // Double rAF: schedule the flip after the initial layout frame
      // has been painted with the starting value, so the transition
      // sees a real change and interpolates over its full duration.
      let raf2 = 0;
      const raf1 = window.requestAnimationFrame(() => {
        raf2 = window.requestAnimationFrame(() => setTimerMounted(true));
      });
      return () => {
        window.cancelAnimationFrame(raf1);
        if (raf2) window.cancelAnimationFrame(raf2);
      };
    }

    const id = window.setTimeout(() => setTimerMounted(true), delay);
    return () => window.clearTimeout(id);
  }, [delay, reduced, timerMounted]);

  return reduced || timerMounted;
}
