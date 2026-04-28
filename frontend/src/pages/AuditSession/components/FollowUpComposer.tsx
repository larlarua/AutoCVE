import { FormEvent, KeyboardEvent, useCallback, useState } from "react";
import { FileText, Loader2, SendHorizonal } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import type { AuditSessionMessageMode } from "@/shared/api/auditSessions";

export function FollowUpComposer({
  disabled,
  onSubmit,
}: {
  disabled?: boolean;
  onSubmit: (content: string, mode: AuditSessionMessageMode) => Promise<void>;
}) {
  const [content, setContent] = useState("");
  const [submittingMode, setSubmittingMode] = useState<AuditSessionMessageMode | null>(null);

  const submitContent = useCallback(async (mode: AuditSessionMessageMode) => {
    const trimmed = content.trim();
    if (!trimmed || disabled || submittingMode) {
      return;
    }
    setSubmittingMode(mode);
    try {
      await onSubmit(trimmed, mode);
      setContent("");
    } catch (error) {
      console.error("[FollowUpComposer] submit failed", error);
    } finally {
      setSubmittingMode(null);
    }
  }, [content, disabled, onSubmit, submittingMode]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await submitContent("chat");
  }

  async function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) {
      return;
    }
    event.preventDefault();
    await submitContent("chat");
  }

  const isSubmitting = submittingMode !== null;

  return (
    <form className="space-y-3" onSubmit={handleSubmit}>
      <div className="rounded-[24px] border border-[rgba(154,180,163,.35)] bg-[linear-gradient(180deg,rgba(255,255,255,.96),rgba(241,247,243,.92))] p-3 shadow-[0_20px_60px_rgba(118,146,126,.08)]">
        <Textarea
          className="min-h-[120px] resize-none rounded-[18px] border-0 bg-transparent px-3 py-3 text-[15px] leading-7 shadow-none focus-visible:ring-0"
          placeholder="Ask a follow-up question, request a report, or ask the agent to summarize the latest finding."
          value={content}
          onChange={(event) => setContent(event.target.value)}
          onKeyDown={(event) => void handleKeyDown(event)}
          disabled={disabled || isSubmitting}
        />
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-[rgba(154,180,163,.2)] px-2 pt-3 text-xs text-muted-foreground">
          <span>Enter sends chat. Shift + Enter adds a new line.</span>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={disabled || isSubmitting || !content.trim()}
              onClick={() => void submitContent("generate_report_and_sync")}
              className="h-11 rounded-full border-[rgba(94,122,99,.22)] bg-white/85 px-5"
            >
              {submittingMode === "generate_report_and_sync" ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <FileText className="mr-2 h-4 w-4" />
              )}
              {submittingMode === "generate_report_and_sync" ? "Syncing..." : "Generate Report"}
            </Button>
            <Button
              type="submit"
              disabled={disabled || isSubmitting || !content.trim()}
              className="h-11 rounded-full bg-[linear-gradient(135deg,#89A98D,#5E7A63)] px-5 text-white shadow-[0_16px_35px_rgba(94,122,99,.22)] hover:opacity-95"
            >
              {submittingMode === "chat" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <SendHorizonal className="mr-2 h-4 w-4" />}
              {submittingMode === "chat" ? "Sending..." : "Send Message"}
            </Button>
          </div>
        </div>
      </div>
    </form>
  );
}
