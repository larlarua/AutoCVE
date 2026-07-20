import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Loader2, PanelRightClose, PanelRightOpen, RefreshCw, Sparkles } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { AuditSessionHeader } from "@/pages/AuditSession/components/AuditSessionHeader";
import { AuditTimeline } from "@/pages/AuditSession/components/AuditTimeline";
import { FollowUpComposer } from "@/pages/AuditSession/components/FollowUpComposer";
import { HandoffTracePanel } from "@/pages/AuditSession/components/HandoffTracePanel";
import { MemoryTracePanel } from "@/pages/AuditSession/components/MemoryTracePanel";
import { SkillTracePanel } from "@/pages/AuditSession/components/SkillTracePanel";
import { ToolTracePanel } from "@/pages/AuditSession/components/ToolTracePanel";
import { useAuditSession } from "@/pages/AuditSession/hooks/useAuditSession";
import { useAuditSessionChatStream } from "@/pages/AuditSession/hooks/useAuditSessionChatStream";
import { useAuditSessionStream } from "@/pages/AuditSession/hooks/useAuditSessionStream";
import type { AuditSessionMessageMode } from "@/shared/api/auditSessions";
import { resumeAuditSession } from "@/shared/api/auditSessions";

export default function AuditSessionPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [resuming, setResuming] = useState(false);
  const { session, messages, setMessages, toolCalls, skills, skillInvocations, memories, handoffs, loading, error, refresh } = useAuditSession(sessionId);
  const { isStreaming, isAutoCompacting, streamError, sendMessage, stopStreaming, streamingAssistantId } = useAuditSessionChatStream({
    sessionId,
    setMessages,
    refresh,
  });

  useAuditSessionStream(() => refresh({ silent: true }), Boolean(sessionId && session?.state === "running" && !isStreaming));

  async function handleSubmit(content: string, mode: AuditSessionMessageMode, selectedSkillRefs: string[] = []) {
    if (!sessionId) {
      return;
    }
    try {
      const result = await sendMessage(content, mode, selectedSkillRefs);
      if (mode === "generate_report_and_sync") {
        const managed = result.synced_managed_vulnerability;
        if (managed) {
          toast.success(`报告已同步到漏洞管理：${managed.vulnerability_name}`);
        } else {
          toast.success("报告生成流程已完成");
        }
        return;
      }
      toast.success("消息已加入会话");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "发送失败");
    }
  }

  async function handleResume() {
    if (!sessionId) return;
    try {
      setResuming(true);
      await resumeAuditSession(sessionId);
      toast.success("已从上一个完整回合继续审计");
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "继续审计失败");
    } finally {
      setResuming(false);
    }
  }

  if (loading) {
    return <div className="p-6 text-sm text-muted-foreground">正在加载审计会话...</div>;
  }

  if (error || !session) {
    return (
      <div className="space-y-4 p-6">
        <Button asChild variant="outline">
          <Link to="/audit-tasks">
            <ArrowLeft className="mr-2 h-4 w-4" />
            返回任务
          </Link>
        </Button>
        <div className="rounded-lg border p-4 text-sm text-destructive">{error || "未找到审计会话。"}</div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[linear-gradient(180deg,#f7f8f6_0%,#eef2ef_46%,#f8faf8_100%)] p-4 lg:p-6">
      <div className="absolute inset-0 cyber-grid-subtle pointer-events-none opacity-28" />
      <div className="relative z-10 mx-auto max-w-[1640px] space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <AuditSessionHeader session={session} />
          {session.can_resume ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => void handleResume()}
              disabled={resuming}
              className="h-11 rounded-full border-amber-200 bg-amber-50 px-4 text-amber-800 hover:bg-amber-100"
            >
              {resuming ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              继续审计
            </Button>
          ) : null}
          {sidebarCollapsed ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => setSidebarCollapsed(false)}
              aria-label="展开侧边栏"
              title="展开侧边栏"
              className="h-11 rounded-full border-[#cfded5] bg-white px-4 text-slate-700 shadow-[0_12px_30px_rgba(54,68,60,0.08)] hover:bg-[#f7faf8]"
            >
              <PanelRightOpen className="mr-2 h-4 w-4" />
              展开记录
            </Button>
          ) : null}
        </div>
        <div className={`grid items-stretch gap-5 ${sidebarCollapsed ? "xl:grid-cols-1" : "xl:grid-cols-[minmax(0,1fr)_440px]"}`}>
          <div className="min-h-[680px] min-w-0 xl:h-[calc(100vh-8.5rem)]">
            <AuditTimeline
              messages={messages}
              isStreaming={isStreaming}
              isAutoCompacting={isAutoCompacting}
              streamError={streamError}
              onStopStreaming={stopStreaming}
              activeStreamingMessageId={streamingAssistantId}
              footer={<FollowUpComposer disabled={false} onSubmit={handleSubmit} />}
            />
          </div>
          {!sidebarCollapsed ? (
            <aside className="min-h-[680px] min-w-0 self-start xl:sticky xl:top-4 xl:h-[calc(100vh-8.5rem)]">
              <div className="flex h-full overflow-hidden rounded-[32px] border border-[#dce5df] bg-white shadow-[0_24px_70px_rgba(54,68,60,0.10)]">
                <div className="flex min-h-0 flex-1 flex-col">
                <div className="flex items-center justify-between gap-3 border-b border-[#e7ece9] bg-[linear-gradient(180deg,#ffffff,#fafcfb)] px-4 py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-[#dce8e1] bg-[linear-gradient(135deg,#ffffff,#f0f7f3)] text-[#5f8069] shadow-sm">
                      <Sparkles className="h-5 w-5" />
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-slate-950">审计记录</p>
                      <p className="truncate text-xs text-slate-500">Trace、交接与记忆记录</p>
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setSidebarCollapsed(true)}
                    aria-label="隐藏侧边栏"
                    title="隐藏侧边栏"
                    className="h-9 rounded-full border-[#d7e4dc] bg-white px-3 text-xs text-slate-600 shadow-sm hover:bg-[#f3f6f4] hover:text-slate-900"
                  >
                    <PanelRightClose className="mr-1.5 h-4 w-4" />
                    隐藏
                  </Button>
                </div>
                <div className="min-h-0 flex-1 divide-y divide-[#e7ece9] overflow-y-auto custom-scrollbar [overflow-wrap:anywhere]">
                  <HandoffTracePanel handoffs={handoffs} />
                  <ToolTracePanel toolCalls={toolCalls} />
                  <SkillTracePanel skills={skills} skillInvocations={skillInvocations} />
                  <MemoryTracePanel memories={memories} />
                </div>
                </div>
              </div>
            </aside>
          ) : null}
        </div>
      </div>
    </div>
  );
}
