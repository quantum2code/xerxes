import { z } from 'zod';
import type { ZapJob } from './job.js';
import { idSchema } from './client.js';
import { scanError } from '../errors.js';
import type { Engine2Error } from '../types.js';

export async function passiveAlerts(job: ZapJob, signal: AbortSignal): Promise<{ alerts: unknown[]; truncated: boolean; errors: Engine2Error[] }> {
  const alerts: unknown[] = []; const errors: Engine2Error[] = [];
  while (alerts.length <= job.config.maxFindings) {
    const count = Math.min(100, job.config.maxFindings + 1 - alerts.length);
    try {
    const page = await job.client.call('alert', 'view', 'alerts', { start: String(alerts.length), count: String(count), contextName: `engine2-${job.scope.id}` },
      z.object({ alerts: z.array(z.unknown()).max(1000) }), signal);
    alerts.push(...page.alerts);
    if (page.alerts.length < count) break;
    } catch (error) { errors.push(scanError('passive', error, signal)); break; }
  }
  return { alerts: alerts.slice(0, job.config.maxFindings), truncated: !!errors.length || alerts.length > job.config.maxFindings, errors };
}
export async function activeAlerts(job: ZapJob, scanId: string, signal: AbortSignal): Promise<{ alerts: unknown[]; truncated: boolean; errors: Engine2Error[] }> {
  const alerts: unknown[] = []; const errors: Engine2Error[] = [];
  let truncated = false;
  try {
  const result = await job.client.call('ascan', 'view', 'alertsIds', { scanId }, z.object({ alertsIds: z.array(idSchema).max(10000) }), signal);
  truncated = result.alertsIds.length > job.config.maxFindings;
  for (const id of [...new Set(result.alertsIds)].slice(0, job.config.maxFindings)) alerts.push((await job.client.call('alert', 'view', 'alert', { id }, z.object({ alert: z.unknown() }), signal)).alert);
  } catch (error) { errors.push(scanError('active', error, signal)); truncated = true; }
  return { alerts, truncated, errors };
}
