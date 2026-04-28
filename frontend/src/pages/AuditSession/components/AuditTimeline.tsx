import { useMemo } from "react";
import { Bot, BrainCircuit, MessageSquareQuote, Square, UserRound, Wrench } from "lucide-react";
import { marked } from "marked";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AuditSessionMessage } from "@/pages/AuditSession/types";

marked.setOptions({ breaks: true, gfm: true });

function formatTimestamp(value?: string) {
  if (!value) {
    return "刚刚";
  }
  return new Date(value).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function rolePresentation(message: AuditSessionMessage) {
  switch (message.role) {
    case "user":
      return {
        label: "提问",
        icon: UserRound,
        bubble:
          "ml-auto max-w-[82%] rounded-[26px] rounded-br-md border border-[rgba(120,156,129,.35)] bg-[linear-gradient(135deg,rgba(233,244,235,.96),rgba(212,232,216,.92))] text-slate-900 shadow-[0_18px_40px_rgba(109,141,116,.12)]",
        align: "justify-end",
      };
    case "assistant":
      return {
        label: "助手",
        icon: Bot,
        bubble:
          "mr-auto max-w-[88%] rounded-[26px] rounded-bl-md border border-[rgba(210,220,214,.9)] bg-white/95 text-slate-900 shadow-[0_28px_60px_rgba(77,102,84,.08)]",
        align: "justify-start",
      };
    case "tool_use":
      return {
        label: "工具调用",
        icon: Wrench,
        bubble:
          "mr-auto max-w-[88%] rounded-[22px] border border-[rgba(237,196,116,.45)] bg-[linear-gradient(135deg,rgba(255,248,233,.95),rgba(252,240,206,.92))] text-amber-950",
        align: "justify-start",
      };
    case "tool_result":
      return {
        label: "工具结果",
        icon: MessageSquareQuote,
        bubble:
          "mr-auto max-w-[88%] rounded-[22px] border border-[rgba(139,166,224,.4)] bg-[linear-gradient(135deg,rgba(238,245,255,.96),rgba(222,236,255,.94))] text-slate-900",
        align: "justify-start",
      };
    default:
      return {
        label: message.role,
        icon: BrainCircuit,
        bubble:
          "mx-auto max-w-[90%] rounded-[22px] border border-[rgba(210,215,220,.7)] bg-[rgba(248,250,252,.92)] text-slate-700",
        align: "justify-center",
      };
  }
}

function renderMarkdown(content: string) {
  return { __html: marked.parse(content || "") as string };
}

export function AuditTimeline({
  messages,
  isStreaming,
  streamError,
  footer,
  onStopStreaming,
  activeStreamingMessageId,
}: {
  messages: AuditSessionMessage[];
  isStreaming?: boolean;
  streamError?: string | null;
  footer?: React.ReactNode;
  onStopStreaming?: () => void;
  activeStreamingMessageId?: string | null;
}) {
  const renderedMessages = useMemo(() => messages, [messages]);

  return (
    <Card className="overflow-hidden rounded-[30px] border border-[rgba(191,208,198,.72)] bg-[linear-gradient(180deg,rgba(255,255,255,.96),rgba(244,249,246,.96))] shadow-[0_28px_90px_rgba(84,110,93,.12)]">
      <CardHeader className="border-b border-[rgba(186,203,193,.45)] bg-[radial-gradient(circle_at_top_left,rgba(214,234,220,.9),rgba(255,255,255,.72)_55%)] pb-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <CardTitle className="text-2xl font-semibold tracking-tight text-slate-900">审计会话</CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">像聊天窗口一样追问审计过程，回答会实时流式展开。</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="rounded-full border border-[rgba(154,180,163,.35)] bg-white/75 px-4 py-2 text-xs text-slate-600 shadow-sm">
              {isStreaming ? "正在生成回复..." : `共 ${messages.length} 条会话消息`}
            </div>
            {isStreaming && onStopStreaming ? (
              <Button
                type="button"
                onClick={onStopStreaming}
                variant="outline"
                className="h-10 rounded-full border-rose-200 bg-rose-50 px-4 text-rose-700 hover:bg-rose-100"
              >
                <Square className="mr-2 h-3.5 w-3.5 fill-current" />
                停止生成
              </Button>
            ) : null}
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="relative">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(99,125,108,.05)_1px,transparent_1px),linear-gradient(90deg,rgba(99,125,108,.05)_1px,transparent_1px)] bg-[size:28px_28px] opacity-50" />
          <div className="relative max-h-[72vh] space-y-5 overflow-y-auto px-5 py-6 sm:px-7">
            {renderedMessages.length === 0 ? (
              <div className="flex min-h-[320px] items-center justify-center">
                <div className="max-w-md rounded-[28px] border border-dashed border-[rgba(154,180,163,.45)] bg-white/70 px-8 py-10 text-center shadow-[0_20px_50px_rgba(120,146,126,.07)]">
                  <Bot className="mx-auto mb-4 h-10 w-10 text-[rgba(94,122,99,.85)]" />
                  <p className="text-base font-medium text-slate-800">会话还没有消息</p>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">审计过程消息、工具调用结果和后续追问都会在这里按聊天形式显示。</p>
                </div>
              </div>
            ) : (
              renderedMessages.map((message) => {
                const presentation = rolePresentation(message);
                const Icon = presentation.icon;
                const isActiveStreamingAssistant = Boolean(
                  isStreaming && message.id === activeStreamingMessageId && message.role === "assistant",
                );
                const emptyStreaming = isActiveStreamingAssistant && !message.content.trim();

                return (
                  <div key={message.id} className={`flex ${presentation.align}`}>
                    <div className={`${presentation.bubble} w-full px-5 py-4 sm:px-6`}>
                      <div className="mb-3 flex items-center justify-between gap-4 text-xs">
                        <div className="flex items-center gap-2 font-medium text-slate-500">
                          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-white/80 shadow-sm ring-1 ring-[rgba(180,194,187,.45)]">
                            <Icon className="h-4 w-4" />
                          </span>
                          <span>{presentation.label}</span>
                          <span className="rounded-full bg-white/80 px-2 py-1 text-[11px] text-slate-400">#{message.sequence}</span>
                        </div>
                        <span className="text-[11px] text-slate-400">{formatTimestamp(message.created_at)}</span>
                      </div>
                      {emptyStreaming ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[rgba(94,122,99,.75)]" />
                          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[rgba(94,122,99,.55)] [animation-delay:120ms]" />
                          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[rgba(94,122,99,.35)] [animation-delay:240ms]" />
                          <span className="ml-2">正在组织回答...</span>
                        </div>
                      ) : (
                        <div className="relative">
                          <div
                            className="audit-markdown max-w-none whitespace-pre-wrap break-words text-[15px] leading-7 text-slate-800 [&_a]:text-[rgb(56,118,92)] [&_a]:underline [&_blockquote]:border-l-4 [&_blockquote]:border-[rgba(126,154,135,.4)] [&_blockquote]:pl-4 [&_code]:rounded-md [&_code]:bg-[rgba(27,31,35,.06)] [&_code]:px-1.5 [&_code]:py-0.5 [&_pre]:overflow-x-auto [&_pre]:rounded-2xl [&_pre]:bg-[rgb(18,24,22)] [&_pre]:p-4 [&_pre]:text-[rgb(231,243,236)] [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_table]:w-full [&_table]:border-collapse [&_td]:border [&_td]:border-[rgba(187,200,193,.7)] [&_td]:px-3 [&_td]:py-2 [&_th]:border [&_th]:border-[rgba(187,200,193,.7)] [&_th]:bg-[rgba(239,246,241,.9)] [&_th]:px-3 [&_th]:py-2 [&_ul]:list-disc [&_ul]:pl-6 [&_ol]:list-decimal [&_ol]:pl-6"
                            dangerouslySetInnerHTML={renderMarkdown(message.content)}
                          />
                          {isActiveStreamingAssistant ? (
                            <span className="ml-1 inline-flex h-6 w-[3px] animate-pulse rounded-full bg-[linear-gradient(180deg,#5E7A63,#9ECB97)] align-middle shadow-[0_0_12px_rgba(94,122,99,.45)]" />
                          ) : null}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
            {streamError ? (
              <div className="mx-auto max-w-2xl rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700 shadow-sm">
                流式回复中断：{streamError}
              </div>
            ) : null}
          </div>
        </div>
        {footer ? <div className="border-t border-[rgba(186,203,193,.45)] bg-[rgba(250,252,250,.92)] p-5 sm:p-6">{footer}</div> : null}
      </CardContent>
    </Card>
  );
}
