import assert from 'node:assert/strict';
import test from 'node:test';
import type { Socket, TcpNetConnectOpts } from 'node:net';
import type { ConnectionOptions } from 'node:tls';
import { buildConnector } from 'undici';
import { createPinnedConnector } from '../src/modules/url-analysis/security/safe-connection.js';
import { loadUrlAnalysisConfig } from '../src/modules/url-analysis/config.js';

const target = new URL('https://example.com/');
const approved = { address: '8.8.8.8', family: 4 };
test('Undici connector pins the approved lookup, preserves hostname/SNI and refuses unverified sockets before callback', async () => {
  for (const peer of ['8.8.8.8', '127.0.0.1', '169.254.169.254', '1.1.1.1']) {
    let destroyed = false;
    const builder: typeof buildConnector = (config) => {
      const options = config as TcpNetConnectOpts & ConnectionOptions;
      assert.equal(options.rejectUnauthorized, true); assert.equal(options.family, 4); assert.equal(options.autoSelectFamily, false);
      (options.lookup as Function)('example.com', {}, (error: unknown, address: string, family: number) => { assert.equal(error, null); assert.equal(address, '8.8.8.8'); assert.equal(family, 4); });
      return (options, callback) => {
        assert.equal(options.hostname, 'example.com'); assert.equal(options.servername, 'example.com');
        callback(null, { remoteAddress: peer, authorized: true, destroy() { destroyed = true; } } as unknown as Socket);
      };
    };
    const connector = createPinnedConnector(target, approved, loadUrlAnalysisConfig({}), builder);
    await new Promise<void>((resolve) => connector({ hostname: 'example.com', protocol: 'https:', port: '443' }, (error, socket) => {
      assert.equal(error === null, peer === '8.8.8.8'); assert.equal(!!socket, peer === '8.8.8.8'); resolve();
    }));
    assert.equal(destroyed, peer !== '8.8.8.8');
  }
});
test('connector refuses changed origins and invalid approved addresses without connecting', () => {
  let connections = 0;
  const connector = createPinnedConnector(target, approved, loadUrlAnalysisConfig({}), () => () => { connections++; });
  connector({ hostname: 'other.example', protocol: 'https:', port: '443' }, (error, _socket) => assert.ok(error));
  assert.equal(connections, 0);
  for (const address of ['127.0.0.1', '::ffff:8.8.8.8', '168.63.129.16']) assert.throws(() => createPinnedConnector(target, { address, family: 4 }, loadUrlAnalysisConfig({})));
});
test('unauthorized TLS sockets are never given to Undici even if a connector incorrectly returns one', async () => {
  const connector = createPinnedConnector(target, approved, loadUrlAnalysisConfig({}), () => (_options, callback) => callback(null,
    { remoteAddress: '8.8.8.8', authorized: false, destroy() {} } as unknown as Socket));
  await new Promise<void>((resolve) => connector({ hostname: 'example.com', protocol: 'https:', port: '443' }, (error, socket) => { assert.ok(error); assert.equal(socket, null); resolve(); }));
});
