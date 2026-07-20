import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { useSearchParams } from "react-router-dom";

import { PageHeader } from "@/pages/AgentDirectAudit/components/PageHeader";
import { ProjectWorkspace } from "@/pages/AgentDirectAudit/components/ProjectWorkspace";
import { SessionWorkspace } from "@/pages/AgentDirectAudit/components/SessionWorkspace";
import type { AgentDirectAuditMode } from "@/pages/AgentDirectAudit/components/ModeSwitcher";
import type { FileEntry } from "@/pages/AgentDirectAudit/components/FileTree";
import {
  filterDirectAuditProjects,
  findUnregisteredManagedDirectories,
  pickDirectAuditProjectId,
} from "@/pages/AgentDirectAudit/lib/projectScope";
import {
  applyQueryFileToWorkspaceTabs,
  reconcileWorkspaceTabsFromFiles,
} from "@/pages/AgentDirectAudit/lib/workspaceFiles";
import { useAuditSession } from "@/pages/AuditSession/hooks/useAuditSession";
import { useAuditSessionChatStream } from "@/pages/AuditSession/hooks/useAuditSessionChatStream";
import { useAuditSessionStream } from "@/pages/AuditSession/hooks/useAuditSessionStream";
import {
  listDirectAuditManagedVulnerabilities,
  listDirectAuditSessions,
  streamCreateDirectAuditSession,
  streamDirectAuditSessionMessage,
  syncLatestDirectAuditManagedVulnerability,
} from "@/shared/api/agentDirectAudit";
import type { AuditSessionMessage, AuditSessionStreamEvent } from "@/shared/api/auditSessions";
import type { ManagedVulnerability } from "@/shared/api/vulnerabilities";
import { api } from "@/shared/config/database";
import type { Project, ProjectFileContent } from "@/shared/types";
import { getLatestDirectAuditReportMessage, getSyncedDirectAuditMessageIds } from "@/shared/utils/directAuditReports";
import { closeFileTab, openFileTab, type WorkspaceTabState } from "@/pages/AgentDirectAudit/lib/workspaceState";

const AUTO_SYNC_REPORTS_STORAGE_KEY = "agent-direct-audit:auto-sync-managed-reports";

function parseMode(value: string | null): AgentDirectAuditMode {
  return value === "workspace" ? "workspace" : "session";
}

function upsertMessage(messages: AuditSessionMessage[], nextMessage: AuditSessionMessage): AuditSessionMessage[] {
  const index = messages.findIndex((message) => message.id === nextMessage.id);
  if (index === -1) {
    return [...messages, nextMessage].sort((left, right) => left.sequence - right.sequence);
  }
  const clone = [...messages];
  clone[index] = nextMessage;
  return clone;
}

type DirectAuditSessionSummary = {
  id: string;
  updated_at: string;
  state: string;
};

function toSessionSummary(
  sessions: Array<{ id: string; updated_at: string; state: string }>,
): DirectAuditSessionSummary[] {
  return sessions.map((item) => ({
    id: item.id,
    updated_at: item.updated_at,
    state: item.state,
  }));
}

export default function AgentDirectAuditPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<AgentDirectAuditMode>(() => parseMode(searchParams.get("mode")));
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [projectSessions, setProjectSessions] = useState<Record<string, DirectAuditSessionSummary[]>>({});
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [projectFiles, setProjectFiles] = useState<FileEntry[]>([]);
  const [workspaceTabs, setWorkspaceTabs] = useState<WorkspaceTabState>({ openTabs: [], activeTabPath: "" });
  const [filePreview, setFilePreview] = useState<ProjectFileContent | null>(null);
  const [filePreviewLoading, setFilePreviewLoading] = useState(false);
  const [filePreviewError, setFilePreviewError] = useState<string | null>(null);
  const [starterPrompt, setStarterPrompt] = useState("");
  const [creatingSession, setCreatingSession] = useState(false);
  const [createAutoCompacting, setCreateAutoCompacting] = useState(false);
  const [createStreamError, setCreateStreamError] = useState<string | null>(null);
  const [managedVulnerabilities, setManagedVulnerabilities] = useState<ManagedVulnerability[]>([]);
  const [managedVulnerabilitiesLoading, setManagedVulnerabilitiesLoading] = useState(false);
  const [syncingManagedVulnerabilities, setSyncingManagedVulnerabilities] = useState(false);
  const [autoSyncManagedReports, setAutoSyncManagedReports] = useState(false);
  const createAbortRef = useRef<AbortController | null>(null);
  const createStreamingAssistantIdRef = useRef<string | null>(null);
  const lastAutoSyncKeyRef = useRef<string | null>(null);

  const queryProjectId = searchParams.get("projectId") || "";
  const querySessionId = searchParams.get("sessionId") || "";
  const queryFilePath = searchParams.get("file") || "";
  const directAuditProjects = useMemo(() => filterDirectAuditProjects(projects), [projects]);
  const selectedProject = directAuditProjects.find((project) => project.id === selectedProjectId) || null;
  const sessionIds = projectSessions[selectedProjectId] || [];

  const { session, messages, setMessages, loading, error, refresh } = useAuditSession(selectedSessionId || undefined);
  const { isStreaming, isAutoCompacting, streamError, sendMessage, stopStreaming, streamingAssistantId } = useAuditSessionChatStream({
    sessionId: selectedSessionId || undefined,
    setMessages,
    refresh,
    streamMessage: streamDirectAuditSessionMessage,
  });

  const activeFilePath = workspaceTabs.activeTabPath;
  const latestReportMatch = useMemo(() => getLatestDirectAuditReportMessage(messages), [messages]);
  const syncedDirectAuditMessageIds = useMemo(
    () => getSyncedDirectAuditMessageIds(managedVulnerabilities),
    [managedVulnerabilities],
  );
  const latestReportMessageId = latestReportMatch?.message.id || null;
  const latestReportSynced = latestReportMessageId ? syncedDirectAuditMessageIds.has(latestReportMessageId) : false;
  const hasLatestReport = Boolean(latestReportMessageId);
  const syncActionDisabled = syncingManagedVulnerabilities || !latestReportMessageId || latestReportSynced;
  const syncActionLabel = !hasLatestReport
    ? "等待报告"
    : latestReportSynced
      ? "已同步"
      : syncingManagedVulnerabilities
        ? "同步中..."
        : "同步报告";
  const timelineStreaming = creatingSession || isStreaming;
  const timelineAutoCompacting = createAutoCompacting || isAutoCompacting;
  const timelineError = createStreamError || streamError || error;
  const timelineStreamingAssistantId = createStreamingAssistantIdRef.current || streamingAssistantId;
  const sessionFailed = session?.state === "failed";

  useAuditSessionStream(
    () => refresh({ silent: true }),
    Boolean(selectedSessionId && session?.state === "running" && !isStreaming),
  );

  useEffect(() => {
    if (window.localStorage.getItem(AUTO_SYNC_REPORTS_STORAGE_KEY) === "true") {
      setAutoSyncManagedReports(true);
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(AUTO_SYNC_REPORTS_STORAGE_KEY, String(autoSyncManagedReports));
  }, [autoSyncManagedReports]);

  useEffect(() => {
    return () => {
      createAbortRef.current?.abort();
      createAbortRef.current = null;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadProjects() {
      setProjectsLoading(true);
      try {
        const [projectsResult, managedDirectoriesResult] = await Promise.allSettled([
          api.getProjects(),
          api.getManagedLocalDirectories(),
        ]);

        if (projectsResult.status !== "fulfilled") {
          throw projectsResult.reason;
        }

        let data = projectsResult.value;
        const managedDirectories =
          managedDirectoriesResult.status === "fulfilled" ? managedDirectoriesResult.value : [];

        const missingManagedDirectories = findUnregisteredManagedDirectories(data, managedDirectories);
        if (missingManagedDirectories.length > 0) {
          const registrationResults = await Promise.allSettled(
            missingManagedDirectories.map((directory) =>
              api.createProject({
                name: directory.name,
                source_type: "local_directory",
                local_path: directory.path,
                workspace_mode: "in_place",
                default_branch: "main",
                programming_languages: [],
              }),
            ),
          );

          if (cancelled) {
            return;
          }

          const nonDuplicateFailures = registrationResults.filter(
            (result) =>
              result.status === "rejected" &&
              !(result.reason instanceof Error && result.reason.message.includes("already registered")),
          );

          if (registrationResults.some((result) => result.status === "fulfilled") || nonDuplicateFailures.length !== registrationResults.length) {
            data = await api.getProjects();
          }

          if (nonDuplicateFailures.length > 0) {
            toast.error("部分本地项目目录自动注册失败，已展示其余可用项目。");
          }
        }

        if (cancelled) {
          return;
        }
        setProjects(data);
        const allowedProjects = filterDirectAuditProjects(data);
        setSelectedProjectId((currentProjectId) =>
          pickDirectAuditProjectId({
            projects: allowedProjects,
            currentProjectId,
            queryProjectId,
          }),
        );
      } catch (loadError) {
        if (!cancelled) {
          toast.error(loadError instanceof Error ? loadError.message : "加载项目失败");
        }
      } finally {
        if (!cancelled) {
          setProjectsLoading(false);
        }
      }
    }

    void loadProjects();
    return () => {
      cancelled = true;
    };
  }, [queryProjectId]);

  useEffect(() => {
    const nextProjectId = pickDirectAuditProjectId({
      projects: directAuditProjects,
      currentProjectId: selectedProjectId,
      queryProjectId,
    });

    if (nextProjectId !== selectedProjectId) {
      setSelectedProjectId(nextProjectId);
    }
  }, [directAuditProjects, queryProjectId, selectedProjectId]);

  useEffect(() => {
    if (!selectedProjectId) {
      setProjectSessions({});
      setSelectedSessionId("");
      setProjectFiles([]);
      setWorkspaceTabs({ openTabs: [], activeTabPath: "" });
      setFilePreview(null);
      setFilePreviewError(null);
      return;
    }

    let cancelled = false;

    async function loadProjectFiles() {
      try {
        const files = await api.getProjectFiles(selectedProjectId);
        if (cancelled) {
          return;
        }

        setProjectFiles(files);

        setWorkspaceTabs((current) =>
          reconcileWorkspaceTabsFromFiles({
            files,
            currentState: current,
            queryFilePath,
          }),
        );
      } catch (workspaceError) {
        if (!cancelled) {
          toast.error(workspaceError instanceof Error ? workspaceError.message : "加载 Agent直审工作区失败");
        }
      }
    }

    void loadProjectFiles();
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId]);

  useEffect(() => {
    if (!selectedProjectId || !queryFilePath || projectFiles.length === 0) {
      return;
    }

    setWorkspaceTabs((current) => {
      const next = applyQueryFileToWorkspaceTabs({
        files: projectFiles,
        currentState: current,
        queryFilePath,
      });

      if (
        next.activeTabPath === current.activeTabPath &&
        next.openTabs.length === current.openTabs.length &&
        next.openTabs.every((path, index) => path === current.openTabs[index])
      ) {
        return current;
      }

      return next;
    });
  }, [projectFiles, queryFilePath, selectedProjectId]);

  useEffect(() => {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.set("mode", mode);

    if (selectedProjectId) {
      nextParams.set("projectId", selectedProjectId);
    } else {
      nextParams.delete("projectId");
    }

    if (selectedSessionId) {
      nextParams.set("sessionId", selectedSessionId);
    } else {
      nextParams.delete("sessionId");
    }

    if (activeFilePath) {
      nextParams.set("file", activeFilePath);
    } else {
      nextParams.delete("file");
    }

    if (nextParams.toString() !== searchParams.toString()) {
      setSearchParams(nextParams, { replace: true });
    }
  }, [activeFilePath, mode, searchParams, selectedProjectId, selectedSessionId, setSearchParams]);

  useEffect(() => {
    if (!selectedProjectId || !activeFilePath) {
      setFilePreview(null);
      setFilePreviewError(null);
      setFilePreviewLoading(false);
      return;
    }

    let cancelled = false;

    async function loadFilePreview() {
      setFilePreviewLoading(true);
      setFilePreviewError(null);
      setFilePreview(null);
      try {
        const preview = await api.getProjectFileContent(selectedProjectId, activeFilePath);
        if (cancelled) {
          return;
        }
        setFilePreview(preview);
      } catch (previewError) {
        if (cancelled) {
          return;
        }
        const message = previewError instanceof Error ? previewError.message : "加载文件内容失败";
        setFilePreview(null);
        setFilePreviewError(message);
      } finally {
        if (!cancelled) {
          setFilePreviewLoading(false);
        }
      }
    }

    void loadFilePreview();
    return () => {
      cancelled = true;
    };
  }, [activeFilePath, selectedProjectId]);

  useEffect(() => {
    if (mode !== "session" || directAuditProjects.length === 0) {
      return;
    }

    let cancelled = false;

    async function loadSessionGroups() {
      const entries = await Promise.all(
        directAuditProjects.map(async (project) => {
          try {
            const sessions = await listDirectAuditSessions(project.id);
            return [project.id, toSessionSummary(sessions)] as const;
          } catch (sessionError) {
            console.error("[AgentDirectAudit] Failed to load sessions", project.id, sessionError);
            return [project.id, []] as const;
          }
        }),
      );

      if (!cancelled) {
        setProjectSessions(Object.fromEntries(entries));
      }
    }

    void loadSessionGroups();
    return () => {
      cancelled = true;
    };
  }, [directAuditProjects, mode]);

  useEffect(() => {
    if (!selectedProjectId) {
      setSelectedSessionId("");
      return;
    }

    const availableSessions = projectSessions[selectedProjectId] || [];
    if (availableSessions.length === 0) {
      setSelectedSessionId("");
      return;
    }

    if (availableSessions.some((item) => item.id === selectedSessionId)) {
      return;
    }

    const preferredSessionId = availableSessions.find((item) => item.id === querySessionId)?.id || availableSessions[0]?.id || "";
    if (preferredSessionId !== selectedSessionId) {
      setSelectedSessionId(preferredSessionId);
    }
  }, [projectSessions, querySessionId, selectedProjectId, selectedSessionId]);

  useEffect(() => {
    if (!selectedSessionId) {
      setManagedVulnerabilities([]);
      setManagedVulnerabilitiesLoading(false);
      lastAutoSyncKeyRef.current = null;
      return;
    }

    let cancelled = false;
    setManagedVulnerabilitiesLoading(true);

    void listDirectAuditManagedVulnerabilities(selectedSessionId)
      .then((items) => {
        if (!cancelled) {
          setManagedVulnerabilities(items);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setManagedVulnerabilities([]);
          toast.error(loadError instanceof Error ? loadError.message : "加载报告同步结果失败");
        }
      })
      .finally(() => {
        if (!cancelled) {
          setManagedVulnerabilitiesLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedSessionId]);

  useEffect(() => {
    if (
      !autoSyncManagedReports ||
      !selectedSessionId ||
      !latestReportMessageId ||
      latestReportSynced ||
      syncingManagedVulnerabilities
    ) {
      return;
    }

    const autoSyncKey = `${selectedSessionId}:${latestReportMessageId}`;
    if (lastAutoSyncKeyRef.current === autoSyncKey) {
      return;
    }

    lastAutoSyncKeyRef.current = autoSyncKey;
    void handleSyncLatestReport();
  }, [
    autoSyncManagedReports,
    latestReportMessageId,
    latestReportSynced,
    selectedSessionId,
    syncingManagedVulnerabilities,
  ]);

  async function reloadSessions(projectId = selectedProjectId, selectSessionId?: string) {
    if (!projectId) {
      return;
    }
    const sessions = toSessionSummary(await listDirectAuditSessions(projectId));
    setProjectSessions((current) => ({
      ...current,
      [projectId]: sessions,
    }));
    if (projectId === selectedProjectId) {
      setSelectedSessionId(selectSessionId || sessions[0]?.id || "");
    }
  }

  async function loadManagedVulnerabilities(sessionId: string) {
    setManagedVulnerabilitiesLoading(true);
    try {
      const items = await listDirectAuditManagedVulnerabilities(sessionId);
      setManagedVulnerabilities(items);
    } catch (loadError) {
      setManagedVulnerabilities([]);
      toast.error(loadError instanceof Error ? loadError.message : "加载报告同步结果失败");
    } finally {
      setManagedVulnerabilitiesLoading(false);
    }
  }

  async function handleCreateSession() {
    if (!selectedProjectId) {
      toast.error("请先选择项目");
      return;
    }

    const content = starterPrompt.trim();
    if (!content) {
      toast.error("请输入你想让 finding agent 直审的内容");
      return;
    }

    createAbortRef.current?.abort();
    createAbortRef.current = new AbortController();
    createStreamingAssistantIdRef.current = null;
    setCreateStreamError(null);
    setCreateAutoCompacting(false);
    setCreatingSession(true);

    try {
      let createdSessionId = "";

      await streamCreateDirectAuditSession(
        {
          project_id: selectedProjectId,
          content,
          guardrails_enabled: false,
        },
        {
          signal: createAbortRef.current.signal,
          onEvent: (event: AuditSessionStreamEvent) => {
            if (event.type === "session_created" && event.session_id) {
              createdSessionId = event.session_id;
              setSelectedSessionId(event.session_id);
              setMessages([]);
              setProjectSessions((previous) => {
                const currentSessions = previous[selectedProjectId] || [];
                if (currentSessions.some((item) => item.id === event.session_id)) {
                  return previous;
                }

                return {
                  ...previous,
                  [selectedProjectId]: [
                    {
                      id: event.session_id,
                      updated_at: new Date().toISOString(),
                      state: "running",
                    },
                    ...currentSessions,
                  ],
                };
              });
              return;
            }

            if (event.type === "user_message" && event.message) {
              setCreateStreamError(null);
              setMessages((previous) => upsertMessage(previous, event.message));
              return;
            }

            if (event.type === "assistant_start" && event.message) {
              setCreateStreamError(null);
              createStreamingAssistantIdRef.current = event.message.id;
              setMessages((previous) => upsertMessage(previous, event.message));
              return;
            }

            if (event.type === "token") {
              setCreateStreamError(null);
              const currentStreamingAssistantId = createStreamingAssistantIdRef.current;
              if (!currentStreamingAssistantId) {
                return;
              }
              setMessages((previous) =>
                previous.map((message) =>
                  message.id === currentStreamingAssistantId
                    ? {
                        ...message,
                        content: event.accumulated ?? `${message.content}${event.content ?? ""}`,
                      }
                    : message,
                ),
              );
              return;
            }

            if (event.type === "context_compaction_started") {
              setCreateStreamError(null);
              setCreateAutoCompacting(true);
              return;
            }

            if (event.type === "context_compacted" || event.type === "context_compaction_failed") {
              setCreateAutoCompacting(false);
              return;
            }

            if (event.type === "done" && event.message) {
              setCreateStreamError(null);
              setMessages((previous) => {
                const withoutPlaceholder = previous.filter(
                  (message) => message.id !== createStreamingAssistantIdRef.current,
                );
                return upsertMessage(withoutPlaceholder, event.message);
              });
              createStreamingAssistantIdRef.current = null;
              return;
            }

            if (event.type === "llm_retry") {
              setCreateStreamError(event.message_text || "模型服务暂时不可用，正在自动重试。");
              return;
            }

            if (event.type === "error") {
              setCreateStreamError(event.message_text || "创建会话失败");
            }
          },
        },
      );

      setStarterPrompt("");
      await reloadSessions(selectedProjectId, createdSessionId || undefined);
      if (createdSessionId) {
        toast.success("已创建新的直审会话");
      }
    } catch (createError) {
      if (!(createError instanceof DOMException && createError.name === "AbortError")) {
        const message = createError instanceof Error ? createError.message : "创建直审会话失败";
        setCreateStreamError(message);
        toast.error(message);
      }
    } finally {
      setCreatingSession(false);
      setCreateAutoCompacting(false);
      createAbortRef.current = null;
    }
  }

  async function handleFollowUp(content: string) {
    if (!selectedSessionId) {
      throw new Error("请先选择直审会话");
    }
    try {
      await sendMessage(content);
      await reloadSessions(selectedProjectId, selectedSessionId);
    } catch (followUpError) {
      const message = followUpError instanceof Error ? followUpError.message : "发送追问失败";
      toast.error(message);
      throw followUpError;
    }
  }

  async function handleSyncLatestReport() {
    if (!selectedSessionId) {
      toast.error("请先选择直审会话");
      return;
    }

    setSyncingManagedVulnerabilities(true);
    try {
      const synced = await syncLatestDirectAuditManagedVulnerability(selectedSessionId);
      await loadManagedVulnerabilities(selectedSessionId);
      toast.success(`已同步报告: ${synced.vulnerability_name}`);
    } catch (syncError) {
      toast.error(syncError instanceof Error ? syncError.message : "同步报告失败");
    } finally {
      setSyncingManagedVulnerabilities(false);
    }
  }

  function handleStopTimelineStreaming() {
    if (createAbortRef.current) {
      createAbortRef.current.abort();
      return;
    }
    stopStreaming();
  }

  function handleProjectChange(projectId: string) {
    setSelectedProjectId(projectId);
    setSelectedSessionId("");
    setWorkspaceTabs({ openTabs: [], activeTabPath: "" });
    setFilePreview(null);
    setFilePreviewError(null);
  }

  function handleSelectSession(projectId: string, sessionId: string) {
    if (projectId !== selectedProjectId) {
      handleProjectChange(projectId);
    }
    setSelectedSessionId(sessionId);
  }

  function handleModeChange(nextMode: AgentDirectAuditMode) {
    setMode(nextMode);
  }

  function handleOpenFile(path: string) {
    setWorkspaceTabs((current) => openFileTab(current.openTabs, current.activeTabPath, path));
  }

  function handleCloseTab(path: string) {
    setWorkspaceTabs((current) => closeFileTab(current.openTabs, current.activeTabPath, path));
  }

  function handleSelectTab(path: string) {
    setWorkspaceTabs((current) => ({
      ...current,
      activeTabPath: path,
    }));
  }

  return (
    <div className="space-y-6 pb-4">
      <PageHeader
        mode={mode}
        onModeChange={handleModeChange}
        projects={directAuditProjects}
        projectsLoading={projectsLoading}
        selectedProjectId={selectedProjectId}
        selectedProject={selectedProject}
        onProjectChange={handleProjectChange}
      />

      {mode === "session" ? (
        <SessionWorkspace
          projects={directAuditProjects}
          selectedProject={selectedProject}
          selectedProjectId={selectedProjectId}
          projectSessions={projectSessions}
          selectedSessionId={selectedSessionId}
          onSelectSession={handleSelectSession}
          onSelectProject={handleProjectChange}
          starterPrompt={starterPrompt}
          onStarterPromptChange={setStarterPrompt}
          onCreateSession={() => void handleCreateSession()}
          creatingSession={creatingSession}
          messages={messages}
          loading={loading}
          timelineStreaming={timelineStreaming}
          timelineAutoCompacting={timelineAutoCompacting}
          timelineError={timelineError}
          timelineStreamingAssistantId={timelineStreamingAssistantId}
          sessionFailed={sessionFailed}
          onFollowUp={handleFollowUp}
          onStopTimelineStreaming={handleStopTimelineStreaming}
          autoSyncManagedReports={autoSyncManagedReports}
          onAutoSyncManagedReportsChange={setAutoSyncManagedReports}
          syncActionDisabled={syncActionDisabled}
          syncActionLabel={syncActionLabel}
          onSyncLatestReport={() => void handleSyncLatestReport()}
          hasLatestReport={hasLatestReport}
          latestReportSynced={latestReportSynced}
          managedVulnerabilities={managedVulnerabilities}
          managedVulnerabilitiesLoading={managedVulnerabilitiesLoading}
        />
      ) : (
        <ProjectWorkspace
          selectedProject={selectedProject}
          files={projectFiles}
          activeTabPath={activeFilePath}
          openTabs={workspaceTabs.openTabs}
          onOpenFile={handleOpenFile}
          onSelectTab={handleSelectTab}
          onCloseTab={handleCloseTab}
          filePreview={filePreview}
          filePreviewLoading={filePreviewLoading}
          filePreviewError={filePreviewError}
        />
      )}
    </div>
  );
}
