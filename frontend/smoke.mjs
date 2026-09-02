/* Headless smoke test: load the SPA against a running Artemis, log in, click
   through Dashboard / Assets / Vulnerabilities, and fail on any console error.
   Usage: node smoke.mjs [baseUrl] [user] [pass] */
import puppeteer from 'puppeteer-core';

const BASE = process.argv[2] || 'http://localhost:5005';
const TOKEN = process.argv[3] || process.env.ARTEMIS_TOKEN || '';

const CHROME =
  ['/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/opt/google/chrome/chrome'].find(
    (p) => {
      try {
        return require('fs').existsSync(p);
      } catch {
        return false;
      }
    },
  ) || '/usr/bin/chromium';

const errors = [];
const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  args: ['--no-sandbox', '--disable-gpu'],
});
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900 });
page.on('console', (m) => {
  if (m.type() === 'error') errors.push(`console: ${m.text()}`);
});
page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));

async function shot(name) {
  await page.screenshot({ path: `smoke-${name}.png` });
}

try {
  if (TOKEN) {
    const u = new URL(BASE);
    await browser.setCookie({
      name: 'artemis_token',
      value: TOKEN,
      domain: u.hostname,
      path: '/',
      httpOnly: true,
    });
  }
  await page.goto(BASE + '/', { waitUntil: 'networkidle2', timeout: 20000 });

  await page.waitForSelector('h1', { timeout: 15000 });
  const dashTitle = await page.$eval('h1', (el) => el.textContent);
  console.log('dashboard h1:', dashTitle);
  await page.waitForNetworkIdle({ timeout: 15000 }).catch(() => {});
  await shot('dashboard');

  // Count rendered panels + any recharts svg
  const panels = await page.$$eval('section.panel', (els) => els.length);
  const svgs = await page.$$eval('svg.recharts-surface', (els) => els.length);
  console.log(`panels=${panels} recharts=${svgs}`);

  await page.goto(BASE + '/assets', { waitUntil: 'networkidle2', timeout: 20000 });
  await page.waitForSelector('table', { timeout: 15000 });
  const rows = await page.$$eval('tbody tr', (els) => els.length);
  console.log('asset rows:', rows);
  await shot('assets');

  for (const route of ['vulnerabilities', 'scan', 'sites', 'schedules', 'agents', 'settings', 'data-query']) {
    await page.goto(BASE + '/' + route, { waitUntil: 'networkidle2', timeout: 20000 });
    await page.waitForSelector('h1', { timeout: 15000 });
    await page.waitForNetworkIdle({ timeout: 8000 }).catch(() => {});
    const h1 = await page.$eval('h1', (el) => el.textContent);
    console.log(`/${route} -> "${h1}"`);
    await shot(route);
  }

  // tablet width
  await page.setViewport({ width: 768, height: 1024 });
  await page.goto(BASE + '/', { waitUntil: 'networkidle2', timeout: 20000 });
  await page.waitForNetworkIdle({ timeout: 10000 }).catch(() => {});
  await shot('dashboard-tablet');
} catch (e) {
  errors.push(`flow: ${e.message}`);
}

await browser.close();

if (errors.length) {
  console.error('\nSMOKE FAILED:\n' + errors.join('\n'));
  process.exit(1);
}
console.log('\nSMOKE OK');
