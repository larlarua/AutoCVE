import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const sourceRoot = resolve(import.meta.dirname, "..");
test("login screen uses the deployment branding configuration", () => {
  const loginSource = readFileSync(resolve(sourceRoot, "pages/Login.tsx"), "utf8");

  assert.match(loginSource, /productName/);
  assert.match(loginSource, /defaultLandingPath/);
  assert.match(loginSource, /alt=\{productName\}/);
  assert.match(loginSource, /\/autocve_icon\.svg/);
});

test("home shell uses the deployment branding configuration", () => {
  const sidebarSource = readFileSync(resolve(sourceRoot, "components/layout/Sidebar.tsx"), "utf8");

  assert.match(sidebarSource, /productName/);
  assert.match(sidebarSource, /defaultLandingPath/);
  assert.match(sidebarSource, /alt=\{productName\}/);
  assert.match(sidebarSource, /\/autocve_icon\.svg/);
});

test("branding configuration preserves the OSS default and supports the internal name", () => {
  const brandingSource = readFileSync(resolve(sourceRoot, "shared/config/branding.ts"), "utf8");

  assert.match(brandingSource, /VITE_INTERNAL_BRANDING/);
  assert.match(brandingSource, /"AIAudit"/);
  assert.match(brandingSource, /"AutoCVE"/);
});

test("internal branding hides the home menu item", () => {
  const routesSource = readFileSync(resolve(sourceRoot, "app/routes.tsx"), "utf8");

  assert.match(routesSource, /visible: !internalBrandingEnabled/);
});

test("browser title uses the deployment branding configuration", () => {
  const appSource = readFileSync(resolve(sourceRoot, "app/App.tsx"), "utf8");

  assert.match(appSource, /document\.title = productName/);
});
