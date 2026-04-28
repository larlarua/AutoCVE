import test from "node:test";
import assert from "node:assert/strict";

import type { ManagedLocalDirectory, Project } from "../../../shared/types/index.ts";

import {
  filterDirectAuditProjects,
  findUnregisteredManagedDirectories,
  pickDirectAuditProjectId,
} from "./projectScope.ts";

function makeProject(overrides: Partial<Project> & Pick<Project, "id" | "name" | "source_type">): Project {
  return {
    id: overrides.id,
    name: overrides.name,
    source_type: overrides.source_type,
    description: "",
    repository_url: "",
    repository_type: "other",
    local_path: "",
    workspace_mode: "",
    default_branch: "main",
    programming_languages: "",
    owner_id: "owner-1",
    is_active: true,
    created_at: "2026-04-20T00:00:00.000Z",
    updated_at: "2026-04-20T00:00:00.000Z",
    ...overrides,
  };
}

function makeManagedDirectory(overrides: Partial<ManagedLocalDirectory> & Pick<ManagedLocalDirectory, "name" | "path">): ManagedLocalDirectory {
  return {
    name: overrides.name,
    path: overrides.path,
    ...overrides,
  };
}

test("filterDirectAuditProjects keeps only managed local-directory projects", () => {
  const projects = [
    makeProject({ id: "repo-1", name: "repo", source_type: "repository" }),
    makeProject({ id: "local-1", name: "pixelfed", source_type: "local_directory", local_path: "D:/projects/pix" }),
    makeProject({ id: "zip-1", name: "archive", source_type: "zip", local_path: "D:/tmp/archive" }),
    makeProject({ id: "local-2", name: "server", source_type: "local_directory", local_path: "D:/projects/server" }),
  ];

  const result = filterDirectAuditProjects(projects);

  assert.deepEqual(
    result.map((project) => project.id),
    ["local-1", "local-2"],
  );
});

test("pickDirectAuditProjectId preserves the current project when it is still allowed", () => {
  const projects = filterDirectAuditProjects([
    makeProject({ id: "local-1", name: "pixelfed", source_type: "local_directory" }),
    makeProject({ id: "local-2", name: "server", source_type: "local_directory" }),
  ]);

  const result = pickDirectAuditProjectId({
    projects,
    currentProjectId: "local-2",
    queryProjectId: "local-1",
  });

  assert.equal(result, "local-2");
});

test("pickDirectAuditProjectId prefers the query project when the current project is invalid", () => {
  const projects = filterDirectAuditProjects([
    makeProject({ id: "local-1", name: "pixelfed", source_type: "local_directory" }),
    makeProject({ id: "local-2", name: "server", source_type: "local_directory" }),
  ]);

  const result = pickDirectAuditProjectId({
    projects,
    currentProjectId: "zip-1",
    queryProjectId: "local-2",
  });

  assert.equal(result, "local-2");
});

test("pickDirectAuditProjectId falls back to the first available managed project", () => {
  const projects = filterDirectAuditProjects([
    makeProject({ id: "local-1", name: "pixelfed", source_type: "local_directory" }),
    makeProject({ id: "local-2", name: "server", source_type: "local_directory" }),
  ]);

  const result = pickDirectAuditProjectId({
    projects,
    currentProjectId: "",
    queryProjectId: "repo-1",
  });

  assert.equal(result, "local-1");
});

test("findUnregisteredManagedDirectories returns managed directories not yet registered as local_directory projects", () => {
  const projects = [
    makeProject({
      id: "local-1",
      name: "pixelfed",
      source_type: "local_directory",
      local_path: "D:/workspace/projects/Pixelfed-16.3.0",
    }),
    makeProject({
      id: "repo-1",
      name: "remote",
      source_type: "repository",
      local_path: "D:/workspace/projects/repo-clone",
    }),
  ];
  const managedDirectories = [
    makeManagedDirectory({
      name: "Pixelfed-16.3.0",
      path: "D:\\workspace\\projects\\Pixelfed-16.3.0\\",
    }),
    makeManagedDirectory({
      name: "Piwigo-16.3.0",
      path: "D:\\workspace\\projects\\Piwigo-16.3.0",
    }),
  ];

  const result = findUnregisteredManagedDirectories(projects, managedDirectories);

  assert.deepEqual(result, [managedDirectories[1]]);
});
