/** Shared execution contract; detector-specific result types retain their own semantics. */
export abstract class ThreatDetectionModule<TInput, TOutput> {
  abstract readonly name: string;
  abstract analyze(input: TInput): TOutput | Promise<TOutput>;
}
