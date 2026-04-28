import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ChevronLeft, ChevronRight, PanelRightClose, PanelRightOpen } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { AuditSessionHeader } from "@/pages/AuditSession/components/AuditSessionHeader";
import { AuditTimeline } from "@/pages/AuditSession/components/AuditTimeline";
import { FindingsSidebar } from "@/pages/AuditSession/components/FindingsSidebar";
import { FollowUpComposer } from "@/pages/AuditSession/components/FollowUpComposer";
import { HandoffTracePanel } from "@/pages/AuditSession/components/HandoffTracePanel";
import { MemoryTracePanel } from "@/pages/AuditSession/components/MemoryTracePanel";
import { SkillTracePanel } from "@/pages/AuditSession/components/SkillTracePanel";
import { ToolTracePanel } from "@/pages/AuditSession/components/ToolTracePanel";
import { useAuditSession } from "@/pages/AuditSession/hooks/useAuditSession";
import { useAuditSessionChatStream } from "@/pages/AuditSession/hooks/useAuditSessionChatStream";
import { useAuditSessionStream } from "@/pages/AuditSession/hooks/useAuditSessionStream";
import type { AuditSessionMessageMode } from "@/shared/api/auditSessions";

export default function AuditSessionPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const { session, messages, setMessages, toolCalls, skills, skillInvocations, memories, handoffs, loading, error, refresh } = useAuditSession(sessionId);
  const { isStreaming, streamError, sendMessage, stopStreaming, streamingAssistantId } = useAuditSessionChatStream({
    sessionId,
    setMessages,
    refresh,
  });

  useAuditSessionStream(() => refresh({ silent: true }), Boolean(sessionId && session?.state === "running" && !isStreaming));

  async function handleSubmit(content: string, mode: AuditSessionMessageMode) {
    if (!sessionId) {
      return;
    }
    try {
      const result = await sendMessage(content, mode);
      if (mode === "generate_report_and_sync") {
        const managed = result.synced_managed_vulnerability;
        if (managed) {
          toast.success(`Report synced to vulnerability management: ${managed.vulnerability_name}`);
        } else {
          toast.success("Report generation flow completed");
        }
        return;
      }
      toast.success("Follow-up added to session");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Follow-up failed");
    }
  }

  if (loading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading audit session...</div>;
  }

  if (error || !session) {
    return (
      <div className="space-y-4 p-6">
        <Button asChild variant="outline">
          <Link to="/audit-tasks">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Tasks
          </Link>
        </Button>
        <div className="rounded-lg border p-4 text-sm text-destructive">{error || "Audit session not found."}</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen space-y-6 bg-[radial-gradient(circle_at_top_left,rgba(215,233,220,.45),transparent_32%),linear-gradient(180deg,rgba(247,250,248,.92),rgba(242,247,244,.98))] p-6">
      <div className="flex items-center justify-between gap-4">
        <Button asChild variant="outline" className="rounded-full border-[rgba(179,197,186,.8)] bg-white/80 shadow-sm backdrop-blur">
          <Link to="/audit-tasks">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Tasks
          </Link>
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => setSidebarCollapsed((value) => !value)}
          className="rounded-full border-[rgba(179,197,186,.8)] bg-white/80 shadow-sm backdrop-blur"
        >
          {sidebarCollapsed ? <PanelRightOpen className="mr-2 h-4 w-4" /> : <PanelRightClose className="mr-2 h-4 w-4" />}
          {sidebarCollapsed ? "Show Sidebar" : "Hide Sidebar"}
          {sidebarCollapsed ? <ChevronLeft className="ml-2 h-4 w-4" /> : <ChevronRight className="ml-2 h-4 w-4" />}
        </Button>
      </div>
      <AuditSessionHeader session={session} />
      <div className={`grid gap-6 ${sidebarCollapsed ? "xl:grid-cols-1" : "xl:grid-cols-[minmax(0,1.7fr)_minmax(340px,0.9fr)]"}`}>
        <div className="space-y-6">
          <AuditTimeline
            messages={messages}
            isStreaming={isStreaming}
            streamError={streamError}
            onStopStreaming={stopStreaming}
            activeStreamingMessageId={streamingAssistantId}
            footer={<FollowUpComposer disabled={false} onSubmit={handleSubmit} />}
          />
        </div>
        {!sidebarCollapsed ? (
          <div className="space-y-6">
            <FindingsSidebar session={session} />
            <HandoffTracePanel handoffs={handoffs} />
            <ToolTracePanel toolCalls={toolCalls} />
            <SkillTracePanel skills={skills} skillInvocations={skillInvocations} />
            <MemoryTracePanel memories={memories} />
          </div>
        ) : null}
      </div>
    </div>
  );
}
