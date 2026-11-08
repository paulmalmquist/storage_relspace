import { readFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

// Optional work-computer browser check. Playwright belongs to the test environment.
export async function browserStory(origins) {
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright');
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH,
    args: ['--disable-dev-shm-usage', '--disable-gpu'],
  });
  const errors = [];
  const context = await browser.newContext({
    viewport: { width: 1180, height: 760 },
    acceptDownloads: true,
  });
  const page = await context.newPage();
  page.on('pageerror', (e) => errors.push(e.message));
  async function enter(origin, user) {
    await page.goto(origin + '/_demo/accounts');
    await page.getByRole('button', { name: 'Open as ' + user }).click();
    await page.locator('#editor').waitFor({ state: 'visible' });
  }
  async function screen(name) {
    if (process.env.DC_SCREENSHOTS) {
      await mkdir(process.env.DC_SCREENSHOTS, { recursive: true });
      await page.screenshot({ path: join(process.env.DC_SCREENSHOTS, name + '.png') });
    }
  }
  try {
    await enter(origins[0], 'Alice');
    const note = 'Verify the torque record · ' + randomUUID().slice(0, 8);
    await page.locator('#note').fill(note);
    await page.locator('#status').selectOption('Blocked');
    await page.getByRole('button', { name: 'Save note', exact: true }).click();
    await page.getByText(note, { exact: true }).waitFor();
    await page.reload();
    await page.getByText(note, { exact: true }).waitFor();
    await screen('readiness-notes');
    await enter(origins[0], 'Bob');
    assert.equal(await page.getByText(note, { exact: true }).count(), 0);
    await enter(origins[1], 'Alice');
    const followup = 'Supplier confirmed the revised ship date · ' + randomUUID().slice(0, 8);
    const bytes = Buffer.from('Synthetic delivery confirmation\n');
    await page.locator('#note').fill(followup);
    await page.locator('#status').selectOption('Waiting');
    await page
      .locator('#file')
      .setInputFiles({ name: 'confirmation.txt', mimeType: 'text/plain', buffer: bytes });
    await page.getByRole('button', { name: 'Save follow-up', exact: true }).click();
    await page.getByText(followup, { exact: true }).waitFor();
    await enter(origins[1], 'Bob');
    const entry = page.locator('article').filter({ hasText: followup });
    await entry.waitFor();
    const downloadEvent = page.waitForEvent('download');
    await entry.getByRole('button', { name: 'Download evidence' }).click();
    const file = await downloadEvent;
    assert.deepEqual(await readFile(await file.path()), bytes);
    await screen('supplier-evidence');
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
  }
}
