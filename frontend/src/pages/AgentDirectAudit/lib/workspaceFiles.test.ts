import test from "node:test";
import assert from "node:assert/strict";

import type { FileEntry } from "../components/FileTree.tsx";
import {
  applyQueryFileToWorkspaceTabs,
  reconcileWorkspaceTabsFromFiles,
} from "./workspaceFiles.ts";

const files: FileEntry[] = [
  { path: "README.md", size: 64 },
  { path: "src/app.ts", size: 128 },
  { path: "src/main.ts", size: 256 },
];

test("reconcileWorkspaceTabsFromFiles seeds the query file when no retained tabs remain", () => {
  const state = reconcileWorkspaceTabsFromFiles({
    files,
    currentState: {
      openTabs: ["missing.ts"],
      activeTabPath: "missing.ts",
    },
    queryFilePath: "src/main.ts",
  });

  assert.deepEqual(state.openTabs, ["src/main.ts"]);
  assert.equal(state.activeTabPath, "src/main.ts");
});

test("reconcileWorkspaceTabsFromFiles preserves retained tabs when refreshing the file list", () => {
  const state = reconcileWorkspaceTabsFromFiles({
    files,
    currentState: {
      openTabs: ["src/app.ts", "missing.ts"],
      activeTabPath: "src/app.ts",
    },
    queryFilePath: "src/main.ts",
  });

  assert.deepEqual(state.openTabs, ["src/app.ts"]);
  assert.equal(state.activeTabPath, "src/app.ts");
});

test("applyQueryFileToWorkspaceTabs focuses the requested file without resetting existing tabs", () => {
  const state = applyQueryFileToWorkspaceTabs({
    files,
    currentState: {
      openTabs: ["src/app.ts"],
      activeTabPath: "src/app.ts",
    },
    queryFilePath: "src/main.ts",
  });

  assert.deepEqual(state.openTabs, ["src/app.ts", "src/main.ts"]);
  assert.equal(state.activeTabPath, "src/main.ts");
});

test("applyQueryFileToWorkspaceTabs ignores files that are not part of the loaded project", () => {
  const state = applyQueryFileToWorkspaceTabs({
    files,
    currentState: {
      openTabs: ["src/app.ts"],
      activeTabPath: "src/app.ts",
    },
    queryFilePath: "scripts/missing.ts",
  });

  assert.deepEqual(state.openTabs, ["src/app.ts"]);
  assert.equal(state.activeTabPath, "src/app.ts");
});
