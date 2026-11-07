import assert from 'node:assert/strict';
import test from 'node:test';
import { DAG } from '../src/pipeline/dag.js';
import { ExecutionContext } from '../src/pipeline/execution-context.js';
import { Executor } from '../src/pipeline/executor.js';
import { PipelineRunner } from '../src/pipeline/pipeline-runner.js';
import { StateManager, TaskState } from '../src/pipeline/state-manager.js';
import { Task, type TaskDefinition } from '../src/pipeline/task.js';

const options = { timeout: 5_000 };

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

function executionContext(task: Task, input: unknown = null) {
  const state = new StateManager();
  state.initialize(new DAG([task]));
  return { state, context: new ExecutionContext(input, state) };
}

for (const mode of ['sync', 'async'] as const) {
  test(`executor retries ${mode} transient failures without recording intermediate errors`, options, async () => {
    const failures = [new Error('first attempt'), new Error('second attempt')];
    const delays: number[] = [];
    const contexts: ExecutionContext[] = [];
    let attempts = 0;
    const handler = (context: ExecutionContext) => {
      contexts.push(context);
      assert.equal(context.state.getState('work'), TaskState.RUNNING);
      assert.deepEqual(context.state.getErrors(), {});
      assert.deepEqual(context.results, {});
      assert.equal(context.state.getResult('work'), undefined);
      attempts += 1;
      if (attempts <= failures.length) throw failures[attempts - 1];
      return 'output';
    };
    const task = new Task({
      name: 'work', retry: { maxRetries: 2 },
      run: mode === 'sync' ? handler : async (context) => {
        await Promise.resolve();
        return handler(context);
      },
    });
    const { context, state } = executionContext(task);
    const executor = new Executor(async (delayMs) => {
      delays.push(delayMs);
      assert.equal(state.getState('work'), TaskState.RUNNING);
      assert.deepEqual(state.getErrors(), {});
      assert.deepEqual(context.results, {});
    });

    await executor.execute(task, context, state);

    assert.equal(attempts, 3);
    assert.deepEqual(delays, [100, 200]);
    assert.ok(contexts.every((seen) => seen === context));
    assert.equal(state.getState('work'), TaskState.SUCCESS);
    assert.equal(state.getResult('work'), 'output');
    assert.deepEqual(context.results, { work: 'output' });
    assert.deepEqual(state.getErrors(), {});
  });
}

test('retry exhaustion records and rethrows only the final error and does not sleep again', options, async () => {
  const failures = [new Error('first'), new Error('second'), new Error('final')];
  const delays: number[] = [];
  let attempts = 0;
  const task = new Task({
    name: 'work', retry: { maxRetries: 2, initialDelayMs: 4 },
    run: (context) => {
      assert.equal(context.state.getState('work'), TaskState.RUNNING);
      assert.deepEqual(context.state.getErrors(), {});
      throw failures[attempts++];
    },
  });
  const { context, state } = executionContext(task);
  const executor = new Executor(async (delayMs) => { delays.push(delayMs); });

  await assert.rejects(executor.execute(task, context, state), (error: unknown) => {
    assert.strictEqual(error, failures[2]);
    assert.equal(state.getState('work'), TaskState.FAILED);
    assert.strictEqual(state.getErrors().work, failures[2]);
    return true;
  });

  assert.equal(attempts, 3);
  assert.deepEqual(delays, [4, 8]);
  assert.deepEqual(state.getErrors(), { work: failures[2] });
  assert.deepEqual(context.results, {});
  assert.equal(state.getResult('work'), undefined);
});

for (const retry of [undefined, { maxRetries: 0 }] as const) {
  test(`executor does not retry with ${retry ? 'zero retries' : 'no retry policy'}`, options, async () => {
    const failure = new Error('not retried');
    let attempts = 0;
    const delays: number[] = [];
    const task = new Task({ name: 'work', retry, run: () => { attempts += 1; throw failure; } });
    const { context, state } = executionContext(task);
    const executor = new Executor(async (delayMs) => { delays.push(delayMs); });

    await assert.rejects(executor.execute(task, context, state), (error: unknown) => error === failure);

    assert.equal(attempts, 1);
    assert.deepEqual(delays, []);
    assert.equal(state.getState('work'), TaskState.FAILED);
    assert.deepEqual(state.getErrors(), { work: failure });
    assert.deepEqual(context.results, {});
  });
}

test('immediate success neither sleeps nor calls shouldRetry', options, async () => {
  let attempts = 0;
  let predicateCalls = 0;
  const delays: number[] = [];
  const task = new Task({
    name: 'work',
    retry: { maxRetries: 3, shouldRetry: () => { predicateCalls += 1; return true; } },
    run: () => { attempts += 1; return 'done'; },
  });
  const { context, state } = executionContext(task);

  await new Executor(async (delayMs) => { delays.push(delayMs); }).execute(task, context, state);

  assert.equal(attempts, 1);
  assert.equal(predicateCalls, 0);
  assert.deepEqual(delays, []);
  assert.deepEqual(context.results, { work: 'done' });
  assert.equal(state.getState('work'), TaskState.SUCCESS);
  assert.deepEqual(state.getErrors(), {});
});

test('shouldRetry receives original errors, permits retry, and stops on false', options, async () => {
  const transient = { transient: true };
  const permanent = new Error('permanent');
  const seen: unknown[] = [];
  const delays: number[] = [];
  let attempts = 0;
  const task = new Task({
    name: 'work',
    retry: {
      maxRetries: 5,
      shouldRetry: (error) => { seen.push(error); return error === transient; },
    },
    run: () => { attempts += 1; throw attempts === 1 ? transient : permanent; },
  });
  const { context, state } = executionContext(task);

  await assert.rejects(
    new Executor(async (delayMs) => { delays.push(delayMs); }).execute(task, context, state),
    (error: unknown) => error === permanent,
  );

  assert.equal(attempts, 2);
  assert.equal(seen.length, 2);
  assert.strictEqual(seen[0], transient);
  assert.strictEqual(seen[1], permanent);
  assert.deepEqual(delays, [100]);
  assert.equal(state.getState('work'), TaskState.FAILED);
  assert.deepEqual(state.getErrors(), { work: permanent });
  assert.deepEqual(context.results, {});
});

test('shouldRetry false on the first failure prevents both retry and sleep', options, async () => {
  const failure = new Error('do not retry');
  let attempts = 0;
  let predicateCalls = 0;
  const delays: number[] = [];
  const task = new Task({
    name: 'work',
    retry: {
      maxRetries: 3,
      shouldRetry: (error) => {
        predicateCalls += 1;
        assert.strictEqual(error, failure);
        return false;
      },
    },
    run: () => { attempts += 1; throw failure; },
  });
  const { context, state } = executionContext(task);

  await assert.rejects(
    new Executor(async (delayMs) => { delays.push(delayMs); }).execute(task, context, state),
    (error: unknown) => error === failure,
  );

  assert.equal(attempts, 1);
  assert.equal(predicateCalls, 1);
  assert.deepEqual(delays, []);
  assert.equal(state.getState('work'), TaskState.FAILED);
  assert.deepEqual(state.getErrors(), { work: failure });
});

test('a throwing shouldRetry fails with the predicate error without retrying or sleeping', options, async () => {
  const original = new Error('handler failure');
  const predicateFailure = new Error('predicate failure');
  let attempts = 0;
  let predicateCalls = 0;
  const delays: number[] = [];
  const task = new Task({
    name: 'work',
    retry: {
      maxRetries: 3,
      shouldRetry: (error) => {
        predicateCalls += 1;
        assert.strictEqual(error, original);
        throw predicateFailure;
      },
    },
    run: () => { attempts += 1; throw original; },
  });
  const { context, state } = executionContext(task);

  await assert.rejects(
    new Executor(async (delayMs) => { delays.push(delayMs); }).execute(task, context, state),
    (error: unknown) => error === predicateFailure,
  );

  assert.equal(attempts, 1);
  assert.equal(predicateCalls, 1);
  assert.deepEqual(delays, []);
  assert.equal(state.getState('work'), TaskState.FAILED);
  assert.deepEqual(state.getErrors(), { work: predicateFailure });
  assert.deepEqual(context.results, {});
});

for (const [label, retry, expected] of [
  ['custom cap', { maxRetries: 5, initialDelayMs: 7, maxDelayMs: 20 }, [7, 14, 20, 20, 20]],
  ['default cap', { maxRetries: 10 }, [100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 30000]],
  ['zero delay', { maxRetries: 3, initialDelayMs: 0, maxDelayMs: 0 }, [0, 0, 0]],
  ['maximum timer delay', { maxRetries: 2, initialDelayMs: 2147483647, maxDelayMs: 2147483647 }, [2147483647, 2147483647]],
] as const) {
  test(`injected sleep observes exponential backoff with ${label}`, options, async () => {
    let attempts = 0;
    const delays: number[] = [];
    const task = new Task({
      name: 'work', retry,
      run: () => {
        attempts += 1;
        if (attempts <= retry.maxRetries) throw new Error(`attempt ${attempts}`);
        return 'recovered';
      },
    });
    const { context, state } = executionContext(task);

    await new Executor(async (delayMs) => { delays.push(delayMs); }).execute(task, context, state);

    assert.equal(attempts, retry.maxRetries + 1);
    assert.deepEqual(delays, expected);
    assert.deepEqual(context.results, { work: 'recovered' });
    assert.deepEqual(state.getErrors(), {});
  });
}

test('Task normalizes retry defaults into a frozen copy without freezing the caller policy', options, () => {
  const shouldRetry = () => true;
  const policy = { maxRetries: 2, shouldRetry };
  const task = new Task({ name: 'work', retry: policy, run: () => undefined });

  assert.notStrictEqual(task.retry, policy);
  assert.deepEqual(task.retry, { maxRetries: 2, initialDelayMs: 100, maxDelayMs: 30000, shouldRetry });
  assert.equal(Object.isFrozen(task.retry), true);
  assert.equal(Object.isFrozen(policy), false);
  policy.maxRetries = 8;
  policy.shouldRetry = () => false;
  assert.equal(task.retry!.maxRetries, 2);
  assert.strictEqual(task.retry!.shouldRetry, shouldRetry);
  assert.throws(() => { Object.assign(task.retry!, { maxRetries: 9 }); }, TypeError);
  assert.equal(task.retry!.maxRetries, 2);
  const plain = new Task({ name: 'plain', run: () => undefined });
  assert.deepEqual(plain.retry, { maxRetries: 0, initialDelayMs: 100, maxDelayMs: 30000, shouldRetry: undefined });
  assert.equal(Object.isFrozen(plain.retry), true);

  const custom = { maxRetries: 1, initialDelayMs: 4, maxDelayMs: 12 };
  const configured = new Task({ name: 'custom', retry: custom, run: () => undefined });
  custom.initialDelayMs = 10;
  custom.maxDelayMs = 20;
  assert.equal(configured.retry!.initialDelayMs, 4);
  assert.equal(configured.retry!.maxDelayMs, 12);
  assert.equal(Object.isFrozen(configured.retry), true);
});

test('Task rejects invalid maxRetries and accepts nonnegative safe-integer boundaries', options, () => {
  for (const maxRetries of [-1, -0.5, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => new Task({ name: 'work', retry: { maxRetries }, run: () => undefined }),
      `maxRetries=${maxRetries} must be rejected`,
    );
  }
  for (const maxRetries of [0, 1, Number.MAX_SAFE_INTEGER]) {
    const task = new Task({ name: 'work', retry: { maxRetries }, run: () => undefined });
    assert.equal(task.retry!.maxRetries, maxRetries);
  }
});

test('Task validates both delays as integers in the timer range', options, () => {
  for (const key of ['initialDelayMs', 'maxDelayMs'] as const) {
    for (const value of [-1, -0.5, 0.5, NaN, Infinity, -Infinity, 2147483648]) {
      const retry = { maxRetries: 1, initialDelayMs: 0, maxDelayMs: 2147483647, [key]: value };
      assert.throws(
        () => new Task({ name: 'work', retry, run: () => undefined }),
        `${key}=${value} must be rejected`,
      );
    }
  }
  for (const value of [0, 2147483647]) {
    const task = new Task({
      name: 'work', retry: { maxRetries: 1, initialDelayMs: value, maxDelayMs: value },
      run: () => undefined,
    });
    assert.equal(task.retry!.initialDelayMs, value);
    assert.equal(task.retry!.maxDelayMs, value);
  }
});

test('Task rejects an initial delay above the cap, including normalized defaults', options, () => {
  const invalid: NonNullable<TaskDefinition['retry']>[] = [
    { maxRetries: 1, initialDelayMs: 11, maxDelayMs: 10 },
    { maxRetries: 1, initialDelayMs: 30001 },
    { maxRetries: 1, maxDelayMs: 99 },
    { maxRetries: 0, initialDelayMs: 1, maxDelayMs: 0 },
  ];
  for (const retry of invalid) {
    assert.throws(() => new Task({ name: 'work', retry, run: () => undefined }));
  }
});

test('runner keeps a retrying root RUNNING and dependents PENDING while unrelated work completes', options, async (t) => {
  const unrelatedFinished = deferred();
  const secondStarted = deferred();
  const releaseSecond = deferred();
  t.after(() => releaseSecond.resolve());
  let attempts = 0;
  let childCalls = 0;
  let context!: ExecutionContext;
  const runner = new PipelineRunner(new DAG([
    new Task({
      name: 'child', dependencies: ['retrying'],
      run: (current) => { childCalls += 1; return `${current.results.retrying}!`; },
    }),
    new Task({
      name: 'retrying', retry: { maxRetries: 1, initialDelayMs: 0 },
      run: async (current) => {
        context = current;
        attempts += 1;
        if (attempts === 1) throw new Error('transient');
        secondStarted.resolve();
        await releaseSecond.promise;
        return 'recovered';
      },
    }),
    new Task({ name: 'unrelated', run: () => 'independent' }),
    new Task({
      name: 'unrelatedChild', dependencies: ['unrelated'],
      run: () => { unrelatedFinished.resolve(); return 'independent child'; },
    }),
  ]));
  let settled = false;
  const run = runner.run(null);
  void run.then(() => { settled = true; }, () => { settled = true; });

  await Promise.all([secondStarted.promise, unrelatedFinished.promise]);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(attempts, 2);
  assert.equal(childCalls, 0);
  assert.equal(settled, false);
  assert.deepEqual(context.state.getStates(), {
    retrying: TaskState.RUNNING, child: TaskState.PENDING,
    unrelated: TaskState.SUCCESS, unrelatedChild: TaskState.SUCCESS,
  });
  assert.deepEqual(context.state.getErrors(), {});
  assert.deepEqual(context.results, { unrelated: 'independent', unrelatedChild: 'independent child' });

  releaseSecond.resolve();
  const result = await run;

  assert.equal(attempts, 2);
  assert.equal(childCalls, 1);
  assert.deepEqual(result, {
    unrelated: 'independent', unrelatedChild: 'independent child', retrying: 'recovered', child: 'recovered!',
  });
  assert.deepEqual(context.state.getStates(), {
    retrying: TaskState.SUCCESS, child: TaskState.SUCCESS,
    unrelated: TaskState.SUCCESS, unrelatedChild: TaskState.SUCCESS,
  });
  assert.deepEqual(context.state.getErrors(), {});
});

test('runner blocks descendants only after exhaustion and retains the final failure', options, async () => {
  const failures = [new Error('transient'), new Error('final')];
  let attempts = 0;
  let blockedCalls = 0;
  let context!: ExecutionContext;
  const run = new PipelineRunner(new DAG([
    new Task({ name: 'grandchild', dependencies: ['child'], run: () => { blockedCalls += 1; } }),
    new Task({ name: 'child', dependencies: ['broken'], run: () => { blockedCalls += 1; } }),
    new Task({
      name: 'broken', retry: { maxRetries: 1, initialDelayMs: 0 },
      run: (current) => {
        context = current;
        assert.equal(current.state.getState('broken'), TaskState.RUNNING);
        assert.equal(current.state.getState('child'), TaskState.PENDING);
        assert.equal(current.state.getState('grandchild'), TaskState.PENDING);
        assert.deepEqual(current.state.getErrors(), {});
        throw failures[attempts++];
      },
    }),
    new Task({ name: 'independent', run: () => 'ok' }),
  ])).run(null);

  await assert.rejects(run, (error: unknown) => error === failures[1]);

  assert.equal(attempts, 2);
  assert.equal(blockedCalls, 0);
  assert.deepEqual(context.state.getStates(), {
    broken: TaskState.FAILED, child: TaskState.BLOCKED, grandchild: TaskState.BLOCKED,
    independent: TaskState.SUCCESS,
  });
  assert.deepEqual(context.state.getErrors(), { broken: failures[1] });
  assert.deepEqual(context.results, { independent: 'ok' });
});

test('a shared executor keeps retry counts and backoff local to concurrent and subsequent executions', options, async () => {
  const attempts = new Map<unknown, number>();
  const delays: number[] = [];
  const task = new Task({
    name: 'work', retry: { maxRetries: 2, initialDelayMs: 3 },
    run: (context) => {
      const count = (attempts.get(context.input) ?? 0) + 1;
      attempts.set(context.input, count);
      if (count <= 2) throw new Error(`transient ${count}`);
      return context.input;
    },
  });
  const executor = new Executor(async (delayMs) => { delays.push(delayMs); });
  const first = executionContext(task, 'first');
  const second = executionContext(task, 'second');

  await Promise.all([
    executor.execute(task, first.context, first.state),
    executor.execute(task, second.context, second.state),
  ]);

  assert.deepEqual(delays.slice().sort((a, b) => a - b), [3, 3, 6, 6]);
  const third = executionContext(task, 'third');
  await executor.execute(task, third.context, third.state);
  assert.deepEqual(delays.slice(4), [3, 6]);
  assert.deepEqual([...attempts.values()], [3, 3, 3]);
  for (const { context, state } of [first, second, third]) {
    assert.deepEqual(context.results, { work: context.input });
    assert.equal(state.getState('work'), TaskState.SUCCESS);
    assert.deepEqual(state.getErrors(), {});
  }
});

test('shared runner runs have independent retry budgets and errors after concurrent and sequential runs', options, async () => {
  const failure = new Error('first run exhausted');
  const attempts = new Map<unknown, number>();
  const contexts = new Map<unknown, ExecutionContext>();
  const runner = new PipelineRunner(new DAG([
    new Task({
      name: 'root', retry: { maxRetries: 2, initialDelayMs: 0 },
      run: (context) => {
        contexts.set(context.input, context);
        const count = (attempts.get(context.input) ?? 0) + 1;
        attempts.set(context.input, count);
        assert.deepEqual(context.state.getErrors(), {});
        if (context.input === 'first') throw failure;
        if (count <= 2) throw new Error('transient');
        return context.input;
      },
    }),
    new Task({ name: 'child', dependencies: ['root'], run: (context) => `${context.results.root}!` }),
  ]));

  const first = assert.rejects(runner.run('first'), (error: unknown) => error === failure);
  const second = runner.run('second');
  const [, secondResult] = await Promise.all([first, second]);
  const thirdResult = await runner.run('third');

  assert.deepEqual([...attempts.values()], [3, 3, 3]);
  assert.deepEqual(secondResult, { root: 'second', child: 'second!' });
  assert.deepEqual(thirdResult, { root: 'third', child: 'third!' });
  assert.equal(new Set(contexts.values()).size, 3);
  assert.deepEqual(contexts.get('first')!.state.getStates(), { root: TaskState.FAILED, child: TaskState.BLOCKED });
  assert.deepEqual(contexts.get('first')!.state.getErrors(), { root: failure });
  for (const input of ['second', 'third']) {
    assert.deepEqual(contexts.get(input)!.state.getStates(), { root: TaskState.SUCCESS, child: TaskState.SUCCESS });
    assert.deepEqual(contexts.get(input)!.state.getErrors(), {});
  }
});
