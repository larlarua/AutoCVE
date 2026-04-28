import type { ManagedLocalDirectory, Project } from "../../../shared/types/index.ts";

function normalizeLocalDirectoryPath(path: string | undefined): string {
  return String(path || "")
    .replace(/\\/g, "/")
    .replace(/\/+$/, "")
    .trim()
    .toLowerCase();
}

export function filterDirectAuditProjects(projects: Project[]): Project[] {
  return projects.filter((project) => project.source_type === "local_directory");
}

export function findUnregisteredManagedDirectories(
  projects: Project[],
  managedDirectories: ManagedLocalDirectory[],
): ManagedLocalDirectory[] {
  const registeredPaths = new Set(
    projects
      .filter((project) => project.source_type === "local_directory")
      .map((project) => normalizeLocalDirectoryPath(project.local_path)),
  );

  return managedDirectories.filter(
    (directory) => !registeredPaths.has(normalizeLocalDirectoryPath(directory.path)),
  );
}

export function pickDirectAuditProjectId({
  projects,
  currentProjectId,
  queryProjectId,
}: {
  projects: Project[];
  currentProjectId?: string;
  queryProjectId?: string;
}): string {
  if (currentProjectId && projects.some((project) => project.id === currentProjectId)) {
    return currentProjectId;
  }

  if (queryProjectId && projects.some((project) => project.id === queryProjectId)) {
    return queryProjectId;
  }

  return projects[0]?.id || "";
}
