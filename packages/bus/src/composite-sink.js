/**
 * Create a sink that forwards to every sink, each guarded.
 *
 * @param {Array<object>} sinks
 * @returns {{ emit: (event: unknown) => boolean, close: () => Promise<void> }}
 */
export function createCompositeSink(sinks) {
  const list = Array.isArray(sinks) ? sinks : [];
  return {
    emit(event) {
      let ok = false;
      for (const sink of list) {
        try {
          const result = sink.emit(event);
          if (result) ok = true;
        } catch {
          /* One sink failing never stops the others. */
        }
      }
      return ok;
    },
    async close() {
      for (const sink of list) {
        try {
          const result = sink.close();
          if (result && typeof result.then === "function") await result;
        } catch {
          /* Close failures are ignored. */
        }
      }
    },
  };
}
