import { expect, test } from '@playwright/test';

test('login, project and sources, every navigation section, reload, logout', async ({ page }) => {
  const failures: string[] = [];
  page.on('pageerror', error => failures.push(error.message));
  await page.goto('/');
  await page.getByLabel('Email', { exact: true }).fill('admin@example.test');
  await page.getByLabel('Пароль', { exact: true }).fill(process.env.E2E_ADMIN_PASSWORD!);
  await page.getByRole('button', { name: 'Войти в систему' }).click();
  await expect(page.getByRole('heading', { name: 'Безопасность под контролем' })).toBeVisible();
  await page.getByRole('link', { name: 'Проекты', exact: true }).click();
  await expect(page.locator('main header h1')).toHaveText('Проекты');
  await page.getByRole('button', { name: /Добавить/ }).click();
  await page.getByLabel('Название', { exact: true }).fill('Browser integration project');
  await page.locator('.modal').getByRole('button', { name: 'Добавить', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'Browser integration project', exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('cell', { name: 'Browser integration project', exact: true })).toBeVisible();
  for (const [section, label, reference, cell] of [
    ['Образы', 'OCI image', 'nginx:1.27', 'registry-1.docker.io/library/nginx:1.27'],
    ['GitHub', 'GitHub repository', 'https://github.com/Kkukusik/RizenVuln', 'Kkukusik/RizenVuln'],
  ]) {
    await page.getByRole('link', { name: section, exact: true }).click();
    await expect(page.locator('main header h1')).toHaveText(section);
    await page.getByRole('button', { name: /Добавить/ }).click();
    await page.locator('.modal').getByRole('combobox').selectOption({ label: 'Browser integration project' });
    await page.getByLabel(label, { exact: true }).fill(reference);
    await page.locator('.modal').getByRole('button', { name: 'Добавить', exact: true }).click();
    await expect(page.getByRole('cell', { name: cell, exact: true })).toBeVisible();
  }
  for (const section of ['Образы', 'GitHub', 'Уязвимости', 'SBOM Explorer', 'Развёртывания', 'Обновления', 'Исправления', 'Отчёты', 'Уведомления', 'Интеграции', 'Настройки']) {
    await page.getByRole('link', { name: section, exact: true }).click();
    await expect(page.locator('main header h1')).toHaveText(section);
    await expect(page.getByRole('alert')).toHaveCount(0);
  }
  // Admin creates a viewer and rotates its password through the actual forms.
  await page.getByLabel('Email', { exact: true }).fill('viewer@example.test');
  await page.getByLabel('Пароль', { exact: true }).fill(process.env.E2E_ADMIN_PASSWORD!);
  await page.getByRole('combobox', { name: /^Роль/ }).selectOption('viewer');
  await page.getByRole('button', { name: 'Создать', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'viewer@example.test', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: /^Пользователь/ }).selectOption({ label: 'viewer@example.test' });
  const viewerPassword = 'browser-fixture-' + crypto.randomUUID();
  await page.getByLabel('Новый пароль', { exact: true }).fill(viewerPassword);
  const reset = page.waitForResponse(response => response.url().includes('/password') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Сменить пароль', exact: true }).click();
  expect((await reset).status()).toBe(200);
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Войти в систему' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Войти в систему' })).toBeVisible();
  await page.getByLabel('Email', { exact: true }).fill('viewer@example.test');
  await page.getByLabel('Пароль', { exact: true }).fill(viewerPassword);
  await page.getByRole('button', { name: 'Войти в систему' }).click();
  await expect(page.getByRole('heading', { name: 'Безопасность под контролем' })).toBeVisible();
  await page.getByRole('link', { name: 'Проекты', exact: true }).click();
  await expect(page.locator('main header h1')).toHaveText('Проекты');
  await expect(page.getByRole('cell', { name: 'Browser integration project', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /Добавить/ })).toHaveCount(0);
  await page.getByRole('link', { name: 'Настройки', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Пользователи', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Войти в систему' })).toBeVisible();
  expect(failures).toEqual([]);
});

test('wrong credentials show a useful error and keep protected UI hidden', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Email', { exact: true }).fill('admin@example.test');
  await page.getByLabel('Пароль', { exact: true }).fill('invalid-password');
  await page.getByRole('button', { name: 'Войти в систему' }).click();
  await expect(page.getByRole('alert')).toContainText('Неверный email или пароль');
  await expect(page.getByRole('link', { name: 'Проекты', exact: true })).toHaveCount(0);
});
