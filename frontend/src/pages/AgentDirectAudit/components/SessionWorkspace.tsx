import { Loader2, MessageSquareText, Plus, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { AuditTimeline } from "@/pages/AuditSession/components/AuditTimeline";
import { FollowUpComposer } from "@/pages/AuditSession/components/FollowUpComposer";
import { ReportSummaryCard } from "@/pages/AgentDirectAudit/components/ReportSummaryCard";
import type { AuditSessionMessage } from "@/shared/api/auditSessions";
import type { ManagedVulnerability } from "@/shared/api/vulnerabilities";
import type { Project } from "@/shared/types";
import { cn } from "@/shared/utils/utils";

const panelClass =
  "overflow-hidden rounded-[30px] border border-[rgba(177,200,185,.38)] bg-[linear-gradient(180deg,rgba(255,255,255,.97),rgba(243,248,244,.94))] shadow-[0_24px_60px_rgba(96,120,101,.08)]";

type SessionSummary = {
  id: string;
  updated_at: string;
  state: string;
};

function formatSessionTime(value?: string) {
  if (!value) {
    return "--";
  }

  return new Date(value).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function SessionSidebar({
  projects,
  projectSessions,
  selectedProjectId,
  selectedSessionId,
  onSelectProject,
  onSelectSession,
  onCreateSession,
  creatingSession,
  selectedProject,
  starterPrompt,
  autoSyncManagedReports,
  onAutoSyncManagedReportsChange,
  syncActionDisabled,
  syncActionLabel,
  onSyncLatestReport,
  hasLatestReport,
  latestReportSynced,
  managedVulnerabilities,
  managedVulnerabilitiesLoading,
}: {
  projects: Project[];
  projectSessions: Record<string, SessionSummary[]>;
  selectedProjectId: string;
  selectedSessionId: string;
  onSelectProject: (projectId: string) => void;
  onSelectSession: (projectId: string, sessionId: string) => void;
  onCreateSession: () => void;
  creatingSession: boolean;
  selectedProject: Project | null;
  starterPrompt: string;
  autoSyncManagedReports: boolean;
  onAutoSyncManagedReportsChange: (checked: boolean) => void;
  syncActionDisabled: boolean;
  syncActionLabel: string;
  onSyncLatestReport: () => void;
  hasLatestReport: boolean;
  latestReportSynced: boolean;
  managedVulnerabilities: ManagedVulnerability[];
  managedVulnerabilitiesLoading: boolean;
}) {
  return (
    <aside className={`${panelClass} min-h-[720px] xl:max-h-[720px] xl:min-h-0`}>
      <div className="border-b border-[rgba(177,200,185,.28)] bg-[radial-gradient(circle_at_top_left,rgba(225,239,228,.92),rgba(255,255,255,.72)_62%)] px-5 py-5">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-[18px] border border-[rgba(177,200,185,.32)] bg-white/80 text-[rgb(94,122,99)]">
              <MessageSquareText className="h-4.5 w-4.5" />
            </span>
            <div className="min-w-0">
              <div className="text-base font-semibold text-slate-900">会话管理</div>
              <div className="truncate text-xs text-slate-500">{selectedProject?.name || "未选择项目"}</div>
            </div>
          </div>
          <Button
            type="button"
            size="sm"
            onClick={onCreateSession}
            disabled={!selectedProjectId || creatingSession || !starterPrompt.trim()}
            className="h-9 rounded-full bg-[linear-gradient(135deg,#89A98D,#5E7A63)] px-4 text-white shadow-[0_10px_24px_rgba(94,122,99,.18)] hover:opacity-95 disabled:opacity-70"
          >
            {creatingSession ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Plus className="mr-1.5 h-4 w-4" />}
            新会话
          </Button>
        </div>
      </div>

      <div className="flex h-[calc(100%-88px)] flex-col">
        <ScrollArea className="flex-1 px-3 py-4">
          <div className="space-y-3">
            {projects.map((project) => {
              const sessions = projectSessions[project.id] || [];
              const activeProject = project.id === selectedProjectId;

              return (
                <section
                  key={project.id}
                  className={cn(
                    "rounded-[24px] border p-3 transition",
                    activeProject
                      ? "border-[rgba(124,163,133,.4)] bg-[rgba(244,249,246,.98)] shadow-[0_14px_28px_rgba(94,122,99,.08)]"
                      : "border-[rgba(177,200,185,.2)] bg-white/74",
                  )}
                >
                  <button
                    type="button"
                    onClick={() => onSelectProject(project.id)}
                    className="flex w-full items-center justify-between gap-3 rounded-[18px] px-3 py-2 text-left transition hover:bg-white/70"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-slate-900">{project.name}</div>
                      <div className="text-xs text-slate-500">{sessions.length} 个会话</div>
                    </div>
                    <Badge variant="outline" className="rounded-full border-[rgba(177,200,185,.28)] bg-white/90 text-slate-500">
                      项目
                    </Badge>
                  </button>

                  <div className="mt-2 space-y-1.5">
                    {sessions.length === 0 ? (
                      <div className="rounded-[16px] border border-dashed border-[rgba(177,200,185,.26)] px-3 py-3 text-xs text-slate-400">
                        暂无会话
                      </div>
                    ) : (
                      sessions.map((item, index) => {
                        const activeSession = item.id === selectedSessionId && activeProject;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => onSelectSession(project.id, item.id)}
                            className={cn(
                              "w-full rounded-[18px] border px-3 py-3 text-left transition",
                              activeSession
                                ? "border-[rgba(124,163,133,.56)] bg-[linear-gradient(135deg,rgba(124,163,133,.96),rgba(94,122,99,.98))] text-white shadow-[0_14px_28px_rgba(94,122,99,.18)]"
                                : "border-[rgba(177,200,185,.22)] bg-white/88 hover:bg-white",
                            )}
                          >
                            <div className="flex items-start justify-between gap-3">
                              <div className="min-w-0">
                                <div className="truncate text-sm font-medium">会话 {sessions.length - index}</div>
                                <div className={cn("mt-1 text-xs", activeSession ? "text-white/75" : "text-slate-500")}>
                                  {formatSessionTime(item.updated_at)}
                                </div>
                              </div>
                              <Badge
                                variant="outline"
                                className={cn(
                                  "rounded-full",
                                  activeSession
                                    ? "border-white/18 bg-white/10 text-white"
                                    : "border-[rgba(177,200,185,.28)] bg-white/80 text-slate-500",
                                )}
                              >
                                {item.state}
                              </Badge>
                            </div>
                          </button>
                        );
                      })
                    )}
                  </div>
                </section>
              );
            })}
          </div>
        </ScrollArea>

        <div className="border-t border-[rgba(177,200,185,.24)] p-3">
          <ReportSummaryCard
            autoSyncManagedReports={autoSyncManagedReports}
            onAutoSyncChange={onAutoSyncManagedReportsChange}
            syncActionDisabled={syncActionDisabled}
            syncActionLabel={syncActionLabel}
            onSyncLatestReport={onSyncLatestReport}
            hasLatestReport={hasLatestReport}
            latestReportSynced={latestReportSynced}
            managedVulnerabilities={managedVulnerabilities}
            managedVulnerabilitiesLoading={managedVulnerabilitiesLoading}
          />
        </div>
      </div>
    </aside>
  );
}

export function SessionWorkspace({
  projects,
  selectedProject,
  selectedProjectId,
  projectSessions,
  selectedSessionId,
  onSelectSession,
  onSelectProject,
  starterPrompt,
  onStarterPromptChange,
  onCreateSession,
  creatingSession,
  messages,
  loading,
  timelineStreaming,
  timelineError,
  timelineStreamingAssistantId,
  sessionFailed,
  onFollowUp,
  onStopTimelineStreaming,
  autoSyncManagedReports,
  onAutoSyncManagedReportsChange,
  syncActionDisabled,
  syncActionLabel,
  onSyncLatestReport,
  hasLatestReport,
  latestReportSynced,
  managedVulnerabilities,
  managedVulnerabilitiesLoading,
}: {
  projects: Project[];
  selectedProject: Project | null;
  selectedProjectId: string;
  projectSessions: Record<string, SessionSummary[]>;
  selectedSessionId: string;
  onSelectSession: (projectId: string, sessionId: string) => void;
  onSelectProject: (projectId: string) => void;
  starterPrompt: string;
  onStarterPromptChange: (value: string) => void;
  onCreateSession: () => void;
  creatingSession: boolean;
  messages: AuditSessionMessage[];
  loading: boolean;
  timelineStreaming: boolean;
  timelineError: string | null;
  timelineStreamingAssistantId: string | null;
  sessionFailed: boolean;
  onFollowUp: (content: string) => Promise<void>;
  onStopTimelineStreaming: () => void;
  autoSyncManagedReports: boolean;
  onAutoSyncManagedReportsChange: (checked: boolean) => void;
  syncActionDisabled: boolean;
  syncActionLabel: string;
  onSyncLatestReport: () => void;
  hasLatestReport: boolean;
  latestReportSynced: boolean;
  managedVulnerabilities: ManagedVulnerability[];
  managedVulnerabilitiesLoading: boolean;
}) {
  return (
    <section className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
      <SessionSidebar
        projects={projects}
        projectSessions={projectSessions}
        selectedProjectId={selectedProjectId}
        selectedSessionId={selectedSessionId}
        onSelectProject={onSelectProject}
        onSelectSession={onSelectSession}
        onCreateSession={onCreateSession}
        creatingSession={creatingSession}
        selectedProject={selectedProject}
        starterPrompt={starterPrompt}
        autoSyncManagedReports={autoSyncManagedReports}
        onAutoSyncManagedReportsChange={onAutoSyncManagedReportsChange}
        syncActionDisabled={syncActionDisabled}
        syncActionLabel={syncActionLabel}
        onSyncLatestReport={onSyncLatestReport}
        hasLatestReport={hasLatestReport}
        latestReportSynced={latestReportSynced}
        managedVulnerabilities={managedVulnerabilities}
        managedVulnerabilitiesLoading={managedVulnerabilitiesLoading}
      />

      {!selectedSessionId ? (
        <div className={`${panelClass} min-h-[720px]`}>
          <div className="space-y-5 p-6">
            <Textarea
              value={starterPrompt}
              onChange={(event) => onStarterPromptChange(event.target.value)}
              disabled={creatingSession || !selectedProjectId}
              className="min-h-[560px] resize-none rounded-[26px] border border-[rgba(177,200,185,.24)] bg-white/92 px-5 py-5 text-[15px] leading-8 shadow-none focus-visible:ring-[rgba(124,163,133,.3)]"
              placeholder={selectedProjectId ? "输入直审请求..." : "请选择项目"}
            />
            <div className="flex flex-col gap-3 border-t border-[rgba(177,200,185,.22)] pt-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-sm text-slate-500">{selectedProject?.name || "未选择项目"}</div>
              <Button
                type="button"
                onClick={onCreateSession}
                disabled={!selectedProjectId || creatingSession || !starterPrompt.trim()}
                className="h-11 rounded-full bg-[linear-gradient(135deg,#89A98D,#5E7A63)] px-5 text-white shadow-[0_18px_34px_rgba(94,122,99,.22)] hover:opacity-95"
              >
                {creatingSession ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Sparkles className="mr-2 h-4 w-4" />}
                {creatingSession ? "创建中..." : "启动直审"}
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <AuditTimeline
          messages={messages}
          isStreaming={timelineStreaming}
          streamError={timelineError}
          onStopStreaming={onStopTimelineStreaming}
          activeStreamingMessageId={timelineStreamingAssistantId}
          footer={
            <div className="space-y-3">
              {sessionFailed ? (
                <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                  当前会话已失败
                </div>
              ) : null}
              <FollowUpComposer disabled={loading || timelineStreaming} onSubmit={onFollowUp} />
            </div>
          }
        />
      )}
    </section>
  );
}
