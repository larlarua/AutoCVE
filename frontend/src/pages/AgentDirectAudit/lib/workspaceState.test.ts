import test from "node:test";
import assert from "node:assert/strict";

import { closeFileTab, openFileTab, syncActiveFileTab } from "./workspaceState.ts";

test("openFileTab appends a new tab and activates it", () => {
  const state = openFileTab([], "", "src/main.ts");

  assert.deepEqual(state.openTabs, ["src/main.ts"]);
  assert.equal(state.activeTabPath, "src/main.ts");
});

test("openFileTab focuses an existing tab without duplication", () => {
  const state = openFileTab(["src/main.ts", "src/app.ts"], "src/main.ts", "src/app.ts");

  assert.deepEqual(state.openTabs, ["src/main.ts", "src/app.ts"]);
  assert.equal(state.activeTabPath, "src/app.ts");
});

test("closeFileTab preserves the active tab when closing an inactive one", () => {
  const state = closeFileTab(["a.ts", "b.ts", "c.ts"], "b.ts", "a.ts");

  assert.deepEqual(state.openTabs, ["b.ts", "c.ts"]);
  assert.equal(state.activeTabPath, "b.ts");
});

test("closeFileTab activates the previous neighboring tab when closing the active tab", () => {
  const state = closeFileTab(["a.ts", "b.ts", "c.ts"], "b.ts", "c.ts");

  assert.deepEqual(state.openTabs, ["a.ts", "b.ts"]);
  assert.equal(state.activeTabPath, "b.ts");
});

test("closeFileTab clears the active path when the last tab closes", () => {
  const state = closeFileTab(["a.ts"], "a.ts", "a.ts");

  assert.deepEqual(state.openTabs, []);
  assert.equal(state.activeTabPath, "");
});

test("syncActiveFileTab keeps the active file when it still exists", () => {
  const state = syncActiveFileTab(["a.ts", "b.ts"], "b.ts");

  assert.deepEqual(state.openTabs, ["a.ts", "b.ts"]);
  assert.equal(state.activeTabPath, "b.ts");
});

test("syncActiveFileTab falls back to the first tab when the current active tab disappears", () => {
  const state = syncActiveFileTab(["a.ts", "b.ts"], "c.ts");

  assert.deepEqual(state.openTabs, ["a.ts", "b.ts"]);
  assert.equal(state.activeTabPath, "a.ts");
});
