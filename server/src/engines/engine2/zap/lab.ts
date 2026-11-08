import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { z } from 'zod';
import { runDocker, type DockerRunner } from '../../../modules/web-security/integrations/docker.js';
import { Engine2Failure } from '../errors.js';
import type { LabAttestation } from '../scope/validator.js';
import type { Engine2Config } from '../types.js';

/** Read-only inspection of an operator-created, labelled, internal-only fixture network. */
export async function verifyLab(config: Engine2Config, docker: DockerRunner = runDocker, signal?: AbortSignal): Promise<LabAttestation> {
  const network = z.array(z.object({ Id: z.string().min(1), Internal: z.literal(true), Labels: z.record(z.string(), z.string()) })).length(1)
    .parse(JSON.parse(await docker(['network', 'inspect', config.labNetwork], { signal })))[0]!;
  const target = z.array(z.object({ Config: z.object({ Labels: z.record(z.string(), z.string()) }), Mounts: z.array(z.unknown()),
    HostConfig: z.object({ NetworkMode: z.string(), Privileged: z.boolean(), PortBindings: z.record(z.string(), z.unknown()).nullable() }),
    NetworkSettings: z.object({ Networks: z.record(z.string(), z.object({ NetworkID: z.string(), IPAddress: z.string(), GlobalIPv6Address: z.string() })) }) })).length(1)
    .parse(JSON.parse(await docker(['inspect', config.labTargetContainer], { signal })))[0]!;
  const attachment = target.NetworkSettings.Networks[config.labNetwork];
  if (network.Labels['xerxes.engine2.lab'] !== 'true' || target.Config.Labels['xerxes.engine2.fixture'] !== 'true' ||
      !attachment || attachment.NetworkID !== network.Id || Object.keys(target.NetworkSettings.Networks).length !== 1 || target.HostConfig.Privileged ||
      ['host', 'none'].includes(target.HostConfig.NetworkMode) || target.Mounts.length || Object.keys(target.HostConfig.PortBindings ?? {}).length) {
    throw new Engine2Failure('LAB_NOT_ISOLATED', 'Development fixture must be labelled, internal-only and have no host ports or mounts');
  }
  const addresses = [attachment.IPAddress, attachment.GlobalIPv6Address].filter(Boolean);
  if (!addresses.length || addresses.some((a) => !isIP(a) || !['private', 'uniqueLocal'].includes(ipaddr.parse(a).range()))) throw new Engine2Failure('LAB_NOT_ISOLATED', 'Fixture addresses must belong to its private isolated bridge');
  return { networkId: network.Id, addresses, hostname: config.labTargetContainer };
}
