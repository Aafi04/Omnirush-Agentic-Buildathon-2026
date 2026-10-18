import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';

const fixture = `{"schema_version":"1.0","trace_id":"e2e-valid","event_id":"e2e-call","timestamp":"2026-10-18T10:00:00Z","type":"tool_call","call_id":"e2e-c1","tool":"process.exec","arguments":{"argv":["sudo","id"],"cwd":"/workspace","shell":false}}\n`;
const malformed = '{"schema_version":"1.0","trace_id":"bad","event_id":"bad-1","type":"tool_call"}\n';
const baseOrigin = new URL(process.env.AGENTTRACE_BASE_URL ?? 'http://127.0.0.1:4173').origin;

test.beforeEach(async ({ page }) => {
  const pageErrors: Error[] = [];
  page.on('pageerror', error => pageErrors.push(error));
  page.on('requestfailed', request => {
    const url = request.url();
    if (url.startsWith(baseOrigin) && !url.endsWith('/favicon.ico')) {
      throw new Error(`First-party request failed: ${request.method()} ${url} ${request.failure()?.errorText ?? ''}`);
    }
  });
  page.on('response', response => {
    if (response.url().startsWith(baseOrigin) && response.status() >= 500) {
      throw new Error(`First-party HTTP ${response.status()}: ${response.url()}`);
    }
  });
  (page as any).__agenttracePageErrors = pageErrors;
});

test.afterEach(async ({ page }, testInfo) => {
  const errors = (page as any).__agenttracePageErrors as Error[];
  if (errors.length) testInfo.annotations.push({ type: 'pageerror', description: errors.map(error => error.message).join('\n') });
  expect(errors, 'uncaught browser JavaScript exceptions').toEqual([]);
});

test('starts cleanly, explores the six-rule demo, and links evidence', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/AgentTrace/);
  await expect(page.getByRole('heading', { name: 'Your investigation starts here' })).toBeVisible();
  await page.getByRole('button', { name: 'Explore demo' }).click();
  await expect(page.getByRole('heading', { name: 'Explore demo · synthetic forensic recording' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /R001 v1\.0/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: /R006 v1\.0/ })).toBeVisible();
  await expect(page.getByRole('region', { name: 'baseline summary' })).toContainText('Allow1Review7Block0');
  await expect(page.getByRole('region', { name: 'strict summary' })).toContainText('Allow1Review0Block7');
  await expect(page.getByRole('region', { name: 'Per-action policy differences' })).toContainText('Baseline review → Strict block');
  await expect(page.getByRole('region', { name: 'Unknown analysis coverage' })).toContainText('Coverage gaps, not findings');
  await page.getByRole('region', { name: 'Policy interventions' }).getByRole('button', { name: 'forensic-2' }).click();
  await expect(page.locator('#event-forensic-2')).toBeFocused();
  await expect(page.getByRole('region', { name: 'Event evidence' })).toContainText('forensic-2');
  await expect((page as any).__agenttracePageErrors).toEqual([]);
});

test('changes policy locally and preserves evidence navigation', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Explore demo' }).click();
  await expect(page.getByRole('region', { name: 'Event timeline' })).toBeVisible();
  const requestCount = await page.locator('body').evaluate(() => performance.getEntriesByType('resource').filter((entry: any) => entry.name.includes('/api/analyze')).length);
  await page.getByLabel('Replay policy').selectOption('strict');
  await expect(page.getByText('Policy: strict v2.0')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Event timeline' }).getByText('block').first()).toBeVisible();
  const afterCount = await page.locator('body').evaluate(() => performance.getEntriesByType('resource').filter((entry: any) => entry.name.includes('/api/analyze')).length);
  expect(afterCount).toBe(requestCount);
  await page.locator('#event-forensic-1').click();
  await expect(page.locator('#event-forensic-1')).toBeFocused();
  await page.locator('#event-forensic-8').click();
  await expect(page.getByRole('region', { name: 'Event evidence' }).getByText(/Recorded continuation after hypothetical block.*not a prediction/)).toBeVisible();
});

test('uploads valid and malformed JSONL, recovers, and exports sanitized reports', async ({ page }, testInfo) => {
  await page.goto('/');
  const validPath = testInfo.outputPath('valid.jsonl');
  const badPath = testInfo.outputPath('malformed.jsonl');
  await fs.writeFile(validPath, fixture, 'utf8');
  await fs.writeFile(badPath, malformed, 'utf8');
  const input = page.getByLabel('Import JSONL');
  await input.setInputFiles(badPath);
  await expect(page.getByRole('alert')).toContainText('Import rejected: invalid_event at line 1.');
  await expect(page.getByRole('region', { name: 'Event timeline' })).not.toBeVisible();
  await input.setInputFiles(validPath);
  await expect(page.getByRole('heading', { name: 'e2e-valid' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /R002 v1\.0/ })).toBeVisible();
  const jsonDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download JSON' }).click();
  const json = await (await jsonDownload).createReadStream();
  const jsonText = await streamText(json);
  const report = JSON.parse(jsonText);
  expect(report.format_version).toBe('1.0');
  expect(report.source_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(report.comparison.baseline.counts).toEqual({ allow: 0, review: 1, block: 0 });
  expect(report.findings[0].event_ids).toEqual(['e2e-call']);
  expect(report.event_index[0]).not.toHaveProperty('arguments');
  expect(jsonText).not.toContain('"arguments":');
  expect(jsonText).not.toContain('"output":');
  expect((await jsonDownload).suggestedFilename()).toMatch(/^agenttrace-report-[a-f0-9]{12}\.json$/);
  const mdDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download Markdown' }).click();
  const md = await (await mdDownload).createReadStream();
  const markdown = await streamText(md);
  expect(markdown).toContain('# AgentTrace forensic report');
  expect(markdown).toContain('Baseline and strict policy comparison');
  expect(markdown).not.toContain('AGENTTRACE_SYNTHETIC_SECRET_001');
  expect((await mdDownload).suggestedFilename()).toMatch(/^agenttrace-report-[a-f0-9]{12}\.md$/);
});

test('supports desktop, tablet and mobile without document overflow', async ({ page }, testInfo) => {
  for (const [name, width, height] of [['desktop', 1440, 1000], ['tablet', 768, 1024], ['mobile', 390, 844]] as const) {
    await page.setViewportSize({ width, height });
    await page.goto('/');
    await page.getByRole('button', { name: 'Explore demo' }).click();
    await expect(page.getByRole('region', { name: 'baseline summary' })).toBeVisible();
    const overflow = await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth }));
    expect(overflow.scrollWidth, `${name} horizontal overflow`).toBeLessThanOrEqual(overflow.clientWidth + 1);
    await page.screenshot({ path: testInfo.outputPath(`${name}.png`), fullPage: true });
  }
});

test('supports keyboard operation and has no serious axe violations', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Explore demo' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: /R001 v1\.0/ })).toBeVisible();
  await page.getByLabel('Replay policy').focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.getByLabel('Replay policy')).toHaveValue('strict');
  const focused = await page.evaluate(() => {
    const element = document.activeElement;
    if (!element) return false;
    const style = getComputedStyle(element);
    return style.outlineStyle !== 'none' || style.boxShadow !== 'none';
  });
  expect(focused, 'focused element has a visible focus treatment').toBe(true);
  const axe = await new AxeBuilder({ page }).analyze();
  const serious = axe.violations.filter(item => item.impact === 'serious' || item.impact === 'critical');
  expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
  await page.getByRole('link', { name: 'Reports' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#reports')).toBeInViewport();
});

async function streamText(stream: NodeJS.ReadableStream | null): Promise<string> {
  if (!stream) throw new Error('Download stream unavailable');
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}
