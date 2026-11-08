import { expect, test } from '@playwright/test';
import type { AnalysisResult, ModuleKey } from '../src/lib/analysis';
import { getSignalState, mostImportantSignal } from '../src/lib/signal-state';

const base = (module: ModuleKey) => ({ module, status: 'completed' as const, evidence: [], issues: [] });
const report: AnalysisResult = {
  validateUrl: { url: 'https://example.com/', originalUrl: 'https://example.com' },
  basicUrlAnalysis: { ...base('basicUrlAnalysis'), details: { hostname: 'example.com', registrableDomain: 'example.com', subdomain: null, signals: [] } },
  mlPhishingDetection: { ...base('mlPhishingDetection'), details: { phishingProbability: 0.12, threshold: 0.5, prediction: 'not_phishing', modelId: 'test-model' } },
  httpRedirectDetection: { ...base('httpRedirectDetection'), details: { status: 'complete', chain: [{ url: 'https://example.com/', statusCode: 200 }], finalUrl: 'https://example.com/', crossDomain: false, httpsDowngrade: false } },
  brandImpersonation: { ...base('brandImpersonation'), details: { brandsChecked: 82, findings: [] } },
  blacklistCheck: { ...base('blacklistCheck'), status: 'not_configured', issues: ['No sources configured.'], details: { status: 'unknown', matches: [], checkedSources: [] } },
  threatAssessment: { riskLevel: 'unknown', summary: 'Available evidence is incomplete.', findings: [], incompleteModules: [{ module: 'blacklistCheck', status: 'not_configured', issues: ['No sources configured.'] }] },
};

test('empty state and accessible URL validation', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Trust starts with a closer look.' })).toBeVisible();
  await page.getByLabel('URL to inspect').fill('javascript:alert(1)');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.locator('#url-error')).toContainText('HTTP or HTTPS');
  await expect(page.getByLabel('URL to inspect')).toBeFocused();
});

test('renders incomplete evidence, floating detail, and resets without stale findings', async ({ page }) => {
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
  await expect(page.getByText('Not enough information', { exact: true })).toBeVisible();
  await expect(page.getByText('Missing evidence is not an all-clear.', { exact: false })).toBeVisible();
  await expect(page.getByText('Advisory provided by Google', { exact: false })).toHaveCount(0);
  const threatCard = page.getByRole('region', { name: 'Threat intelligence' });
  await threatCard.getByRole('button', { name: 'View evidence' }).click();
  await expect(page.getByRole('dialog', { name: 'Threat intelligence evidence' }).getByText('No sources configured.')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'New scan' }).click();
  await expect(page.getByLabel('URL to inspect')).toHaveValue('');
  await expect(page.getByText('4/5', { exact: true })).toHaveCount(0);
});

test('renders Google advisory only for an actual Google match', async ({ page }) => {
  const matched: AnalysisResult = structuredClone(report);
  matched.blacklistCheck.status = 'completed';
  matched.blacklistCheck.details = { status: 'matched', checkedSources: [{ source: 'google-safe-browsing' }], matches: [{ source: 'google-safe-browsing', details: 'Potentially unsafe URL: SOCIAL_ENGINEERING.' }] };
  matched.threatAssessment.riskLevel = 'high';
  await page.route('**/api/analyze', (route) => route.fulfill({ json: matched }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByRole('link', { name: 'Advisory provided by Google' })).toHaveAttribute('href', 'https://developers.google.com/safe-browsing/v4/advisory');
  await expect(page.getByRole('heading', { name: 'High-risk signals detected.' })).toBeVisible();
});

test('pending request disables repeated submissions; failure preserves input', async ({ page }) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/analyze', async (route) => { await gate; await route.fulfill({ status: 502, json: { error: { message: 'The analysis server is unavailable.' } } }); });
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Analyzing URL' })).toBeDisabled();
  release();
  await expect(page.locator('#url-error')).toContainText('server is unavailable');
  await expect(page.getByLabel('URL to inspect')).toHaveValue('https://example.com');
});

test('desktop sidebar stays docked while the report scrolls', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
  const sidebar = page.getByRole('complementary');
  const before = await sidebar.boundingBox();
  expect(before?.x).toBe(0);
  expect(before?.y).toBe(0);
  expect(before?.height).toBe(900);
  const reportBefore = await page.getByRole('heading', { name: 'Checks', exact: true }).boundingBox();
  await page.evaluate(() => window.scrollTo(0, 500));
  const after = await sidebar.boundingBox();
  expect(after).toEqual(before);
  const reportAfter = await page.getByRole('heading', { name: 'Checks', exact: true }).boundingBox();
  expect(reportAfter!.y).toBeLessThan(reportBefore!.y);
  await expect(page.getByRole('button', { name: 'Analyze URL', exact: true })).toBeInViewport();
});

test('readable typography on desktop and mobile', async ({ page }) => {
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  for (const width of [1440, 820, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    await page.getByLabel('URL to inspect').fill('https://example.com');
    await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
    await expect(page.getByText('4/5', { exact: true })).toBeVisible();
    const description = page.locator('.detector-body p').first();
    await expect(description).toHaveCSS('font-size', '14px');
    await expect(page.locator('.card-heading h3').first()).toHaveCSS('font-size', '15px');
    await expect(page.getByLabel('URL to inspect')).toHaveCSS('font-size', width <= 600 ? '16px' : '14px');
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
});

test('desktop and mobile visual review', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.goto('/');
  await page.screenshot({ path: '/tmp/opencode/xerxes-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '/tmp/opencode/xerxes-mobile.png', fullPage: true });
});

test('mobile layout does not overflow, including long URL results', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  const longReport = structuredClone(report);
  longReport.validateUrl.url = `https://example.com/${'a'.repeat(300)}`;
  longReport.httpRedirectDetection.details.finalUrl = longReport.validateUrl.url;
  await page.route('**/api/analyze', (route) => route.fulfill({ json: longReport }));
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Analyze URL', exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('mobile completion brings the verdict and target into view', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.locator('.report-area')).toBeFocused();
  await expect(page.getByRole('heading', { name: 'The picture is incomplete.' })).toBeInViewport();
  await expect(page.locator('.assessment-target')).toContainText('example.com');
  await page.screenshot({ path: '/tmp/opencode/xerxes-motion-mobile-report.png', fullPage: true });
});

test('scan cancellation preserves the URL and allows retry', async ({ page }) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let first = true;
  await page.route('**/api/analyze', async (route) => {
    if (first) {
      first = false;
      await gate;
      await route.fulfill({ json: report }).catch(() => {});
    } else await route.fulfill({ json: report });
  });
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel scan' }).click();
  await expect(page.getByText('Scan cancelled. Your URL is ready to edit.')).toBeVisible();
  await expect(page.getByLabel('URL to inspect')).toHaveValue('https://example.com');
  await expect(page.getByLabel('URL to inspect')).toBeEnabled();
  release();
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
});

test('copy confirms success and restores its original affordance', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await page.getByRole('button', { name: 'Copy normalized URL' }).click();
  await expect(page.getByRole('button', { name: 'URL copied', exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('https://example.com/');
  await expect(page.getByRole('button', { name: 'Copy normalized URL' })).toBeVisible({ timeout: 5000 });
});

test('reduced motion preserves keyboard evidence and has no animated state panels', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByLabel('URL to inspect').press('Enter');
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
  await expect(page.locator('.assessment-transition > .assessment-content')).toHaveCount(1);
  const card = page.getByRole('region', { name: 'Threat intelligence' });
  await card.getByRole('button', { name: 'View evidence' }).focus();
  await page.keyboard.press('Enter');
  const popup = page.getByRole('dialog', { name: 'Threat intelligence evidence' });
  await expect(popup.getByText('No sources configured.')).toBeVisible();
  await expect(popup).toHaveCSS('transition-duration', '0s');
  await page.keyboard.press('Escape');
  await expect(card.getByRole('button', { name: 'View evidence' })).toBeFocused();
  expect(errors).toEqual([]);
});

test('tablet uses single-column cards based on report width', async ({ page }) => {
  await page.setViewportSize({ width: 820, height: 900 });
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
  const cards = page.locator('.detector-card');
  const first = await cards.nth(0).boundingBox();
  const second = await cards.nth(1).boundingBox();
  expect(second!.x).toBe(first!.x);
  expect(second!.y).toBeGreaterThan(first!.y);
});

test('empty state omits redundant captions and placeholder tiles', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('.detector-card')).toHaveCount(0);
  await expect(page.locator('.check-preview-list li')).toHaveCount(5);
  await expect(page.locator('.assessment-stats')).toHaveCount(0);
  await expect(page.locator('.assessment-meta')).toHaveCount(0);
  await expect(page.locator('.url-overview')).toHaveCount(0);
  await expect(page.getByText('Every link tells a story.')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Analyze URL', exact: true })).toBeVisible();
  await expect(page.locator('#privacy-note')).toBeVisible();
  await expect(page.locator('.report-disclaimer')).toBeVisible();
});

test('signal layers respond to hover and keyboard without running analysis', async ({ page }) => {
  let requests = 0;
  page.on('request', (request) => { if (request.url().endsWith('/api/analyze')) requests++; });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  const diagram = page.getByRole('figure', { name: 'Explore the five URL analysis checks' });
  await expect(diagram.getByRole('button')).toHaveCount(5);
  await diagram.getByRole('button', { name: 'Highlight Phishing detection', exact: true }).hover();
  await expect(diagram.getByRole('button', { name: 'Highlight Phishing detection', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.check-preview-list li[data-active]')).toHaveText('Phishing detection');
  await expect(diagram.locator('g[data-signal="mlPhishingDetection"] .signal-wire-lit')).toHaveCSS('opacity', '1');
  await page.screenshot({ path: '/tmp/opencode/xerxes-signal-hover.png', fullPage: true });
  const brand = diagram.getByRole('button', { name: 'Highlight Brand impersonation', exact: true });
  await brand.focus();
  await page.keyboard.press('Enter');
  await expect(brand).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.check-preview-list li[data-active]')).toHaveText('Brand impersonation');
  expect(requests).toBe(0);
});

test('signal diagram remains static but selectable with reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await expect(page.locator('.signal-tilt')).toHaveCSS('transform', 'none');
  await page.getByRole('button', { name: 'Highlight Redirect trail', exact: true }).hover();
  await expect(page.getByRole('button', { name: 'Highlight Redirect trail', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.signal-tilt')).toHaveCSS('transform', 'none');
  await expect(page.locator('g[data-signal="httpRedirectDetection"]')).toHaveCSS('transform', 'none');
  expect(errors).toEqual([]);
});

test.describe('touch signal exploration', () => {
  test.use({ hasTouch: true, viewport: { width: 390, height: 844 } });
  test('layers can be selected by tapping with no horizontal overflow', async ({ page }) => {
    await page.goto('/');
    const layer = page.getByRole('button', { name: 'Highlight Threat intelligence', exact: true });
    await layer.tap();
    await expect(layer).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.check-preview-list li[data-active]')).toHaveText('Threat intelligence');
    await expect(page.locator('.signal-caption-text > [data-panel-active]')).toHaveText('Threat intelligence');
    await expect(page.locator('g[data-signal="blacklistCheck"] .signal-wire-lit')).toHaveCSS('opacity', '1');
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: '/tmp/opencode/xerxes-signal-touch.png', fullPage: true });
  });
});

test('SVG painter order is bottom-to-top; keyboard order stays top-to-bottom', async ({ page }) => {
  await page.goto('/');
  const order = await page.locator('.signal-svg > g[data-signal]').evaluateAll((groups) => groups.map((group) => group.getAttribute('data-layer-index')));
  expect(order).toEqual(['4', '3', '2', '1', '0']);
  const buttons = await page.locator('.signal-hitarea').evaluateAll((nodes) => nodes.map((node) => node.getAttribute('aria-label')));
  expect(buttons).toEqual(['Highlight URL structure', 'Highlight Phishing detection', 'Highlight Redirect trail', 'Highlight Brand impersonation', 'Highlight Threat intelligence']);
  const plate = page.locator('g[data-signal="basicUrlAnalysis"] .signal-plate');
  expect(await plate.evaluate((node) => Array.from(node.children).findIndex((child) => child.classList.contains('signal-bottom-rim'))
    < Array.from(node.children).findIndex((child) => child.classList.contains('signal-surface')))).toBe(true);
});

test('completed SVG shows real module data, severity-specific alerts, and selected details', async ({ page }) => {
  const risky = structuredClone(report);
  risky.mlPhishingDetection.details.phishingProbability = 0.92;
  risky.mlPhishingDetection.details.prediction = 'phishing';
  risky.brandImpersonation.details.findings = [{ brand: 'Example Brand', reason: 'domain_typo', officialDomains: ['example.org'] }];
  risky.blacklistCheck.status = 'completed';
  risky.blacklistCheck.issues = [];
  risky.blacklistCheck.details = { status: 'matched', matches: [{ source: 'google-safe-browsing', details: 'Potentially unsafe URL: SOCIAL_ENGINEERING.' }], checkedSources: [{ source: 'google-safe-browsing' }] };
  risky.blacklistCheck.evidence = [{ module: 'blacklistCheck', code: 'BLACKLIST_MATCH', hostname: 'example.com', target: 'submitted', source: 'google-safe-browsing' }];
  risky.brandImpersonation.evidence = [{ module: 'brandImpersonation', code: 'BRAND_LOOKALIKE', hostname: 'example.com', target: 'submitted', brand: 'Example Brand' }];
  risky.threatAssessment = {
    riskLevel: 'high', summary: 'Potentially unsafe URL: a trusted source reported a match.', incompleteModules: [],
    findings: [
      { ruleId: 'blacklist-match', severity: 'high', message: 'A trusted blacklist source reported a match.', evidence: risky.blacklistCheck.evidence },
      { ruleId: 'brand-impersonation', severity: 'medium', message: 'Brand resemblance requires review.', evidence: risky.brandImpersonation.evidence },
    ],
  };
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.route('**/api/analyze', (route) => route.fulfill({ json: risky }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  const diagram = page.locator('.signal-diagram[data-report]');
  await expect(diagram).toBeVisible();
  await expect(diagram.locator('g[data-signal="blacklistCheck"]')).toHaveAttribute('data-tone', 'alert');
  await expect(diagram.locator('g[data-signal="blacklistCheck"] .signal-readout')).toHaveText('Match');
  await expect(diagram.locator('g[data-signal="mlPhishingDetection"]')).toHaveAttribute('data-tone', 'notice');
  await expect(diagram.locator('g[data-signal="mlPhishingDetection"] .signal-readout')).toHaveText('92.0%');
  await expect(diagram.locator('g[data-signal="brandImpersonation"]')).toHaveAttribute('data-tone', 'warning');
  await expect(diagram.locator('g[data-tone="alert"]')).toHaveCount(1);
  await expect(diagram.getByRole('button', { name: 'Highlight Threat intelligence', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(diagram.locator('[data-panel-active] .signal-detail')).toHaveText('A trusted blacklist source reported a match.');
  await expect(diagram.locator('g[data-signal="blacklistCheck"] .signal-plate')).toHaveCSS('stroke', 'rgb(242, 152, 137)');
  await page.screenshot({ path: '/tmp/opencode/xerxes-signal-alert-data.png', fullPage: true });
  await diagram.getByRole('button', { name: 'Highlight Phishing detection', exact: true }).click();
  await expect(diagram.locator('[data-panel-active] .signal-detail')).toContainText('not an overall safety score');
  await expect(page.getByRole('region', { name: 'Phishing detection' })).toHaveAttribute('data-selected', 'true');
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/opencode/xerxes-signal-alert-mobile.png', fullPage: true });
  await page.getByRole('button', { name: 'New scan' }).click();
  await expect(page.locator('.signal-diagram[data-report]')).toHaveCount(0);
  await expect(page.locator('g[data-tone="alert"]')).toHaveCount(0);
});

test('unconfigured checks stay unavailable in the result diagram, not passed', async ({ page }) => {
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  const diagram = page.locator('.signal-diagram[data-report]');
  await expect(diagram.locator('g[data-signal="blacklistCheck"]')).toHaveAttribute('data-tone', 'unknown');
  await expect(diagram.locator('g[data-signal="blacklistCheck"] .signal-readout')).toHaveText('Unavailable');
  await expect(diagram.locator('[data-panel-active] .signal-state-label')).toHaveText('Not configured');
  await expect(diagram.getByRole('button', { name: 'Highlight Threat intelligence', exact: true })).toHaveAccessibleDescription(/Unavailable.*Not configured/);
  await expect(diagram.locator('g[data-tone="alert"]')).toHaveCount(0);
});

test('diagram severity is not invented from global risk or a model probability', () => {
  const data = structuredClone(report);
  data.threatAssessment.riskLevel = 'high';
  data.mlPhishingDetection.details.phishingProbability = 0.99;
  data.mlPhishingDetection.details.prediction = 'phishing';
  expect(getSignalState('mlPhishingDetection', data).tone).toBe('notice');
  expect(getSignalState('basicUrlAnalysis', data).tone).toBe('complete');
  expect(getSignalState('blacklistCheck', data).tone).toBe('unknown');
  expect(mostImportantSignal(data)).toBe('mlPhishingDetection');
  expect(getSignalState('mlPhishingDetection', data, true).tone).toBe('pending');
});

test('diagram captions consolidate data and keep card dimensions stable across layers', async ({ page }) => {
  const varied = structuredClone(report);
  varied.blacklistCheck.issues = ['Threat intelligence is unavailable because no provider has been configured. The remaining checks have completed, but missing provider evidence cannot establish safety.'];
  await page.route('**/api/analyze', (route) => route.fulfill({ json: varied }));
  for (const width of [1440, 820, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto('/');
    await page.getByLabel('URL to inspect').fill('https://example.com');
    await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
    await expect(page.locator('.signal-diagram[data-report]')).toBeVisible();
    const sizes = await page.evaluate(async () => {
      const samples: { card: number; caption: number }[] = [];
      const card = document.querySelector('.assessment-card')!;
      const caption = document.querySelector('.signal-diagram[data-report] figcaption')!;
      const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>('.signal-diagram[data-report] .signal-hitarea'));
      for (const button of [...buttons, ...[...buttons].reverse()]) {
        button.focus({ preventScroll: true });
        for (let frame = 0; frame < 8; frame++) {
          await new Promise(requestAnimationFrame);
          samples.push({ card: card.getBoundingClientRect().height, caption: caption.getBoundingClientRect().height });
        }
      }
      return samples;
    });
    expect(Math.max(...sizes.map((sample) => sample.card)) - Math.min(...sizes.map((sample) => sample.card))).toBeLessThan(1);
    expect(Math.max(...sizes.map((sample) => sample.caption)) - Math.min(...sizes.map((sample) => sample.caption))).toBeLessThan(1);
    await expect(page.locator('.signal-info-heading:visible')).toHaveCount(1);
    await expect(page.locator('.signal-detail:visible')).toHaveCount(1);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.screenshot({ path: '/tmp/opencode/xerxes-stable-caption-mobile.png', fullPage: true });
});

test('assessment panels never collapse between loading and completed states', async ({ page }) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/analyze', async (route) => { await gate; await route.fulfill({ json: report }); });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.evaluate(() => {
    const measurements: number[] = [];
    const state = window as unknown as { cardSamples: number[]; measureCard: boolean };
    state.cardSamples = measurements;
    state.measureCard = true;
    const sample = () => {
      if (!state.measureCard) return;
      measurements.push(document.querySelector('.assessment-transition')!.getBoundingClientRect().height);
      requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
  });
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Following the evidence.' })).toBeVisible();
  release();
  await expect(page.getByText('4/5', { exact: true })).toBeVisible();
  const heights = await page.evaluate(async () => {
    for (let frame = 0; frame < 16; frame++) await new Promise(requestAnimationFrame);
    const state = window as unknown as { cardSamples: number[]; measureCard: boolean };
    state.measureCard = false;
    return state.cardSamples;
  });
  expect(heights.length).toBeGreaterThan(5);
  expect(Math.min(...heights)).toBeGreaterThan(250);
});

test('hover expansion floats above the grid without changing neighboring card positions', async ({ page }) => {
  const detailed = structuredClone(report);
  detailed.basicUrlAnalysis.evidence = Array.from({ length: 12 }, (_, index) => ({
    module: 'basicUrlAnalysis' as const, code: 'URL_STRUCTURE', hostname: 'example.com', target: 'submitted', location: 'path', signal: `test-signal-${index}`, value: index,
  }));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.route('**/api/analyze', (route) => route.fulfill({ json: detailed }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  const card = page.getByRole('region', { name: 'URL structure' });
  await card.scrollIntoViewIfNeeded();
  const before = await page.locator('.detector-grid').evaluate((grid) => ({
    height: grid.getBoundingClientRect().height,
    children: Array.from(grid.children).map((node) => ({ top: (node as HTMLElement).offsetTop, left: (node as HTMLElement).offsetLeft, height: (node as HTMLElement).offsetHeight, width: (node as HTMLElement).offsetWidth })),
  }));
  await card.getByRole('button', { name: 'View evidence' }).hover();
  const popup = page.getByRole('dialog', { name: 'URL structure evidence' });
  await expect(popup).toBeVisible();
  const after = await page.locator('.detector-grid').evaluate((grid) => ({
    height: grid.getBoundingClientRect().height,
    children: Array.from(grid.children).map((node) => ({ top: (node as HTMLElement).offsetTop, left: (node as HTMLElement).offsetLeft, height: (node as HTMLElement).offsetHeight, width: (node as HTMLElement).offsetWidth })),
  }));
  expect(after).toEqual(before);
  expect(await popup.evaluate((node) => node.closest('.detector-grid'))).toBeNull();
  const popupBox = await popup.boundingBox();
  expect(popupBox!.y).toBeGreaterThanOrEqual(10);
  expect(popupBox!.y + popupBox!.height).toBeLessThanOrEqual(990);
  await page.screenshot({ path: '/tmp/opencode/xerxes-floating-card.png', fullPage: true });
  await popup.getByRole('button', { name: 'Close evidence' }).click();
  await expect(popup).toBeHidden();
});

test('mobile evidence expansion stays within the viewport and closes without reflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/analyze', (route) => route.fulfill({ json: report }));
  await page.goto('/');
  await page.getByLabel('URL to inspect').fill('https://example.com');
  await page.getByRole('button', { name: 'Analyze URL', exact: true }).click();
  const card = page.getByRole('region', { name: 'Threat intelligence' });
  await card.getByRole('button', { name: 'View evidence' }).scrollIntoViewIfNeeded();
  const height = await page.locator('.detector-grid').evaluate((node) => (node as HTMLElement).offsetHeight);
  await card.getByRole('button', { name: 'View evidence' }).click();
  const popup = page.getByRole('dialog', { name: 'Threat intelligence evidence' });
  await expect(popup.getByText('No sources configured.')).toBeVisible();
  const box = await popup.boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(10);
  expect(box!.x + box!.width).toBeLessThanOrEqual(380);
  expect(box!.y).toBeGreaterThanOrEqual(10);
  expect(box!.y + box!.height).toBeLessThanOrEqual(834);
  expect(await page.locator('.detector-grid').evaluate((node) => (node as HTMLElement).offsetHeight)).toBe(height);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/opencode/xerxes-floating-card-mobile.png', fullPage: true });
  await popup.getByRole('button', { name: 'Close evidence' }).click();
  await expect(popup).toBeHidden();
});
