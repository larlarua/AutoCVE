import type { FileEntry } from "../components/FileTree.tsx";
import { openFileTab, syncActiveFileTab, type WorkspaceTabState } from "./workspaceState.ts";

function buildAvailablePathSet(files: FileEntry[]): Set<string> {
  return new Set(files.map((file) => file.path));
}

export function reconcileWorkspaceTabsFromFiles({
  files,
  currentState,
  queryFilePath,
}: {
  files: FileEntry[];
  currentState: WorkspaceTabState;
  queryFilePath: string;
}): WorkspaceTabState {
  const availablePaths = buildAvailablePathSet(files);
  const retainedTabs = currentState.openTabs.filter((path) => availablePaths.has(path));
  const seededTabs =
    retainedTabs.length > 0
      ? retainedTabs
      : queryFilePath && availablePaths.has(queryFilePath)
        ? [queryFilePath]
        : [];
  const nextActiveCandidate = availablePaths.has(currentState.activeTabPath)
    ? currentState.activeTabPath
    : queryFilePath;

  return syncActiveFileTab(seededTabs, nextActiveCandidate);
}

export function applyQueryFileToWorkspaceTabs({
  files,
  currentState,
  queryFilePath,
}: {
  files: FileEntry[];
  currentState: WorkspaceTabState;
  queryFilePath: string;
}): WorkspaceTabState {
  const availablePaths = buildAvailablePathSet(files);
  const retainedTabs = currentState.openTabs.filter((path) => availablePaths.has(path));
  const syncedState = syncActiveFileTab(
    retainedTabs,
    availablePaths.has(currentState.activeTabPath) ? currentState.activeTabPath : "",
  );

  if (!queryFilePath || !availablePaths.has(queryFilePath)) {
    return syncedState;
  }

  return openFileTab(syncedState.openTabs, syncedState.activeTabPath, queryFilePath);
}
