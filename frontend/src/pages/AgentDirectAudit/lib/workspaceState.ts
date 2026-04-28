export type WorkspaceTabState = {
  openTabs: string[];
  activeTabPath: string;
};

export function openFileTab(openTabs: string[], activeTabPath: string, nextPath: string): WorkspaceTabState {
  if (!nextPath) {
    return { openTabs, activeTabPath };
  }

  if (openTabs.includes(nextPath)) {
    return {
      openTabs,
      activeTabPath: nextPath,
    };
  }

  return {
    openTabs: [...openTabs, nextPath],
    activeTabPath: nextPath,
  };
}

export function closeFileTab(openTabs: string[], activeTabPath: string, targetPath: string): WorkspaceTabState {
  const closingIndex = openTabs.indexOf(targetPath);
  if (closingIndex === -1) {
    return { openTabs, activeTabPath };
  }

  const nextTabs = openTabs.filter((path) => path !== targetPath);
  if (activeTabPath !== targetPath) {
    return {
      openTabs: nextTabs,
      activeTabPath,
    };
  }

  const fallbackPath = nextTabs[closingIndex - 1] || nextTabs[closingIndex] || "";

  return {
    openTabs: nextTabs,
    activeTabPath: fallbackPath,
  };
}

export function syncActiveFileTab(openTabs: string[], activeTabPath: string): WorkspaceTabState {
  if (openTabs.length === 0) {
    return {
      openTabs,
      activeTabPath: "",
    };
  }

  if (activeTabPath && openTabs.includes(activeTabPath)) {
    return {
      openTabs,
      activeTabPath,
    };
  }

  return {
    openTabs,
    activeTabPath: openTabs[0],
  };
}
