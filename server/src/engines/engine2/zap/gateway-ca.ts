import 'reflect-metadata';
import { BasicConstraintsExtension, ExtendedKeyUsage, ExtendedKeyUsageExtension, KeyUsageFlags, KeyUsagesExtension,
  SubjectAlternativeNameExtension, X509CertificateGenerator } from '@peculiar/x509';
import { isIP } from 'node:net';
import type { ServerOptions } from 'node:https';

/** Ephemeral interception PKI only, not Engine 3 certificate analysis. Private keys never leave the worker. */
export async function createGatewayCa(expiresAt: number) {
  const provider = globalThis.crypto;
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
  const keys = await provider.subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const issuer = 'CN=Xerxes Engine2 Ephemeral Gateway';
  const root = await X509CertificateGenerator.createSelfSigned({ name: issuer, keys, signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    notBefore: new Date(Date.now() - 60000), notAfter: new Date(expiresAt + 60000),
    extensions: [new BasicConstraintsExtension(true, 0, true), new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true)] }, provider);
  return {
    certificate: root.toString('pem'),
    async certificateFor(host: string): Promise<ServerOptions> {
      const leafKeys = await provider.subtle.generateKey(algorithm, true, ['sign', 'verify']);
      const certificate = await X509CertificateGenerator.create({ subject: 'CN=Xerxes Scoped Interception', issuer,
        publicKey: leafKeys.publicKey, signingKey: keys.privateKey, signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        notBefore: new Date(Date.now() - 60000), notAfter: new Date(expiresAt + 60000),
        extensions: [new BasicConstraintsExtension(false), new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
          new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth]), new SubjectAlternativeNameExtension([{ type: isIP(host) ? 'ip' : 'dns', value: host }])] }, provider);
      const rawKey = Buffer.from(await provider.subtle.exportKey('pkcs8', leafKeys.privateKey));
      return { key: `-----BEGIN PRIVATE KEY-----\n${rawKey.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`, cert: certificate.toString('pem') };
    },
  };
}
