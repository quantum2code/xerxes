/** Abortable bounded semaphore. No global networking configuration or unbounded work queue. */
export class Semaphore {
  private active = 0;
  private readonly waiting: (() => void)[] = [];
  constructor(private readonly capacity: number, private readonly maxWaiting = 128) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error('Invalid semaphore capacity');
  }
  async run<T>(signal: AbortSignal, work: () => Promise<T>): Promise<T> {
    signal.throwIfAborted();
    if (this.active >= this.capacity) {
      if (this.waiting.length >= this.maxWaiting) throw new Error('Concurrency queue limit reached');
      await new Promise<void>((resolve, reject) => {
        const ready = () => { signal.removeEventListener('abort', aborted); resolve(); };
        const aborted = () => {
          const index = this.waiting.indexOf(ready);
          if (index >= 0) this.waiting.splice(index, 1);
          reject(signal.reason);
        };
        signal.addEventListener('abort', aborted, { once: true });
        this.waiting.push(ready);
      });
      // The departing worker reserved its slot for this waiter.
    } else this.active++;
    try { signal.throwIfAborted(); return await work(); }
    finally {
      const next = this.waiting.shift();
      if (next) next(); else this.active--;
    }
  }
}
