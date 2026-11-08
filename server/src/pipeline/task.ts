import type { ExecutionContext } from './execution-context.js';

export interface RetryPolicy {
  maxRetries: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  shouldRetry?: (error: unknown) => boolean;
}

export interface TaskDefinition {
  name: string;
  dependencies?: readonly string[];
  retry?: RetryPolicy;
  run: (context: ExecutionContext) => unknown;
}

export class Task {
  readonly name: string;
  readonly dependencies: readonly string[];
  readonly retry: Readonly<Required<Omit<RetryPolicy, 'shouldRetry'>> & Pick<RetryPolicy, 'shouldRetry'>>;
  private readonly handler: TaskDefinition['run'];

  constructor(definition: TaskDefinition) {
    this.name = definition.name;
    this.dependencies = Object.freeze([...(definition.dependencies ?? [])]);
    this.handler = definition.run;

    const maxRetries = definition.retry?.maxRetries ?? 0;
    const initialDelayMs = definition.retry?.initialDelayMs ?? 100;
    const maxDelayMs = definition.retry?.maxDelayMs ?? 30_000;
    if (!Number.isSafeInteger(maxRetries) || maxRetries < 0) {
      throw new Error('maxRetries must be a non-negative safe integer');
    }
    for (const [name, value] of Object.entries({ initialDelayMs, maxDelayMs })) {
      // Node timers overflow above this limit and would retry almost immediately.
      if (!Number.isInteger(value) || value < 0 || value > 2_147_483_647) {
        throw new Error(`${name} must be an integer between 0 and 2147483647`);
      }
    }
    if (initialDelayMs > maxDelayMs) {
      throw new Error('initialDelayMs must not exceed maxDelayMs');
    }

    this.retry = Object.freeze({
      maxRetries, initialDelayMs, maxDelayMs,
      shouldRetry: definition.retry?.shouldRetry,
    });
  }

  async run(context: ExecutionContext): Promise<unknown> {
    return this.handler(context);
  }
}
