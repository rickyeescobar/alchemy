/**
 * Minimal push channel between an Effect producer and a mounted Ink view.
 * The view subscribes; the producer emits. Replaces the per-view
 * listener-set boilerplate in the plan/nuke progress views.
 */

export interface EventSource<E> {
  subscribe(listener: (event: E) => void): () => void;
}

export interface EventHub<E> {
  readonly source: EventSource<E>;
  readonly emit: (event: E) => void;
}

export const makeEventHub = <E>(): EventHub<E> => {
  const listeners = new Set<(event: E) => void>();
  const pending: E[] = [];
  let mounted = false;
  return {
    source: {
      subscribe(listener) {
        listeners.add(listener);
        // Ink commits effects after the producer receives its live handle, so
        // events may arrive before the component subscribes. Replay that
        // initial gap once; later subscriptions must not double-apply events.
        if (!mounted) {
          mounted = true;
          for (const event of pending.splice(0)) listener(event);
        }
        return () => listeners.delete(listener);
      },
    },
    emit: (event) => {
      if (!mounted) pending.push(event);
      for (const listener of listeners) listener(event);
    },
  };
};
