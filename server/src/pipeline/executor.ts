import { setTimeout as sleep } from 'node:timers/promises';
import type { ExecutionContext } from './execution-context.js';
import type { StateManager } from './state-manager.js';
import type { Task } from './task.js';

export class Executor {
  constructor(private readonly wait: (delayMs: number) => Promise<void> = sleep) {}

  async execute(task: Task, context: ExecutionContext, state: StateManager): Promise<void> {
    state.markRunning(task.name);
    try {
      const { maxRetries, initialDelayMs, maxDelayMs, shouldRetry } = task.retry;
      let delayMs = initialDelayMs;
      let result: unknown;

      for (let attempt = 0; ; attempt += 1) {
        try {
          result = await task.run(context);
          break;
        } catch (error) {
          if (attempt >= maxRetries || (shouldRetry && !shouldRetry(error))) throw error;
          await this.wait(delayMs);
          delayMs = Math.min(delayMs * 2, maxDelayMs);
        }
      }
      // Define an own property so task names cannot invoke inherited setters.
      Object.defineProperty(context.results, task.name, {
        value: result,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      state.markSuccess(task.name, result);
    } catch (error) {
      state.markFailed(task.name, error);
      throw error;
    }
  }
}
