import { useMemo, useState } from "react";
import { Bot, BrainCircuit, ChevronDown, ChevronRight, ChevronUp, MessageSquareQuote, Square, Terminal, UserRound, Wrench } from "lucide-react";
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

function formatSequence(value: number) {
  return Number.isInteger(value) ? String(value) : "";
}

function rolePresentation(message: AuditSessionMessage) {
  switch (message.role) {
    case "user":
      return {
        label: "提问",
        icon: UserRound,
        bubble:
          "ml-auto max-w-[82%] rounded-[26px] rounded-br-md border border-[#dce5df] bg-[linear-gradient(135deg,#ffffff,#f7f8f6)] text-slate-900 shadow-[0_18px_40px_rgba(54,68,60,.08)]",
        align: "justify-end",
      };
    case "assistant":
      return {
        label: "助手",
        icon: Bot,
        bubble:
          "mr-auto max-w-[88%] rounded-[26px] rounded-bl-md border border-[#e3e8e5] bg-[linear-gradient(135deg,#ffffff,#fbfcfb)] text-slate-900 shadow-[0_28px_60px_rgba(54,68,60,.07)]",
        align: "justify-start",
      };
    case "tool_use":
      return {
        label: "工具调用",
        icon: Wrench,
        bubble:
          "mr-auto max-w-[88%] rounded-[22px] border border-[#efd79d] bg-[linear-gradient(135deg,#fff9eb,#fff3cf)] text-amber-950",
        align: "justify-start",
      };
    case "tool_result":
      return {
        label: "工具结果",
        icon: MessageSquareQuote,
        bubble:
          "mr-auto max-w-[88%] rounded-[22px] border border-[#cddaf3] bg-[linear-gradient(135deg,#f4f8ff,#eaf2ff)] text-slate-900",
        align: "justify-start",
      };
    default:
      return {
        label: message.role,
        icon: BrainCircuit,
        bubble:
          "mx-auto max-w-[90%] rounded-[22px] border border-[#d8dee5] bg-slate-50 text-slate-700",
        align: "justify-center",
      };
  }
}

function renderMarkdown(content: string) {
  return { __html: marked.parse(content || "") as string };
}

const LONG_USER_MESSAGE_CHAR_LIMIT = 900;
const LONG_USER_MESSAGE_LINE_LIMIT = 14;

function isLongUserMessage(content: string) {
  const text = (content || "").trim();
  return text.length > LONG_USER_MESSAGE_CHAR_LIMIT || text.split(/\r?\n/).length > LONG_USER_MESSAGE_LINE_LIMIT;
}

function reasoningContentFrom(message: AuditSessionMessage) {
  const payload = message.payload || {};
  const value = payload.reasoning_content || payload.reasoning || payload.thought;
  return typeof value === "string" ? value.trim() : "";
}

function isThinkingPlaceholder(message: AuditSessionMessage) {
  return message.metadata?.kind === "audit_chat_thinking_placeholder";
}

function isEmptyAssistantWithoutVisibleContent(message: AuditSessionMessage) {
  return (
    message.role === "assistant" &&
    !message.content.trim() &&
    !reasoningContentFrom(message) &&
    !isThinkingPlaceholder(message)
  );
}

type ToolInvocation = {
  id: string;
  toolName: string;
  commandText: string;
  inputText: string;
  resultText: string;
  status?: string;
  durationMs?: number | null;
  useMessage?: AuditSessionMessage;
  resultMessage?: AuditSessionMessage;
};

type TimelineRenderItem =
  | { type: "message"; message: AuditSessionMessage }
  | { type: "tool_group"; id: string; messages: AuditSessionMessage[]; invocations: ToolInvocation[] };

function isToolTimelineMessage(message: AuditSessionMessage) {
  if (message.role === "tool_use" || message.role === "tool_result") {
    return true;
  }
  if (message.role === "system") {
    const content = (message.content || "").trim();
    return message.name === "tool_progress" || /^Starting\s+\S+/.test(content) || /^Completed\s+\S+/.test(content);
  }
  return false;
}

function prettyJson(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function compactText(value: string, max = 180) {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length > max ? `${normalized.slice(0, max - 1)}…` : normalized;
}

function toolNameFrom(message: AuditSessionMessage) {
  return String(message.payload?.tool_name || message.name || message.content || "Tool");
}

function commandFromInput(toolName: string, input: Record<string, unknown>) {
  const name = toolName.toLowerCase();
  if (typeof input.command === "string" && input.command.trim()) {
    return input.command.trim();
  }
  if (name === "read") {
    const path = input.file_path || input.path || input.file || input.file_paths;
    const range = input.start_line || input.end_line ? `:${input.start_line || 1}-${input.end_line || "end"}` : "";
    return `Read ${prettyJson(path)}${range}`;
  }
  if (name === "grep") {
    return `Grep ${prettyJson(input.pattern || input.query || input.keyword)}${input.path ? ` in ${input.path}` : ""}`;
  }
  if (name === "glob") {
    return `Glob ${prettyJson(input.pattern || input.glob || "*")}${input.path ? ` in ${input.path}` : ""}`;
  }
  if (name === "write") {
    return `Write ${prettyJson(input.path)}`;
  }
  if (name === "skill") {
    return `Skill ${prettyJson(input.skill_ref || input.skill || input.name || "")}${input.action ? ` ${input.action}` : ""}`;
  }
  return prettyJson(input) || toolName;
}

function buildTimelineItems(messages: AuditSessionMessage[]): TimelineRenderItem[] {
  const items: TimelineRenderItem[] = [];
  let group: AuditSessionMessage[] = [];

  const flushGroup = () => {
    if (group.length === 0) return;
    const first = group[0];
    const last = group[group.length - 1];
    items.push({
      type: "tool_group",
      id: `tool-group-${first.id}-${last.id}`,
      messages: group,
      invocations: buildToolInvocations(group),
    });
    group = [];
  };

  for (const message of messages) {
    if (isEmptyAssistantWithoutVisibleContent(message)) {
      flushGroup();
      continue;
    }
    if (isToolTimelineMessage(message)) {
      group.push(message);
      continue;
    }
    flushGroup();
    items.push({ type: "message", message });
  }
  flushGroup();
  return items;
}

function buildToolInvocations(messages: AuditSessionMessage[]) {
  const invocations: ToolInvocation[] = [];
  const byToolUseId = new Map<string, ToolInvocation>();

  for (const message of messages) {
    if (message.role === "tool_use") {
      const toolName = toolNameFrom(message);
      const input = (message.payload?.input || {}) as Record<string, unknown>;
      const toolUseId = String(message.payload?.tool_use_id || message.id);
      const invocation: ToolInvocation = {
        id: toolUseId,
        toolName,
        commandText: commandFromInput(toolName, input),
        inputText: prettyJson(input),
        resultText: "",
        useMessage: message,
      };
      invocations.push(invocation);
      byToolUseId.set(toolUseId, invocation);
      continue;
    }

    if (message.role === "tool_result") {
      const toolUseId = String(message.payload?.tool_use_id || "");
      const output = message.payload?.output;
      const resultText = prettyJson(output) || message.content || "";
      const existing = byToolUseId.get(toolUseId);
      if (existing) {
        existing.resultMessage = message;
        existing.resultText = resultText;
        existing.status = String(message.metadata?.status || "");
        existing.durationMs = typeof message.metadata?.duration_ms === "number" ? message.metadata.duration_ms : null;
      } else {
        invocations.push({
          id: message.id,
          toolName: toolNameFrom(message),
          commandText: message.name || toolUseId || "Tool result",
          inputText: "",
          resultText,
          status: String(message.metadata?.status || ""),
          durationMs: typeof message.metadata?.duration_ms === "number" ? message.metadata.duration_ms : null,
          resultMessage: message,
        });
      }
      continue;
    }

    invocations.push({
      id: message.id,
      toolName: message.name || "system",
      commandText: message.content || "Tool progress",
      inputText: "",
      resultText: "",
      status: "progress",
      useMessage: message,
    });
  }

  return invocations;
}

function ToolGroupBlock({
  item,
  groupOpen,
  resultOpen,
  onToggleGroup,
  onToggleResult,
}: {
  item: Extract<TimelineRenderItem, { type: "tool_group" }>;
  groupOpen: boolean;
  resultOpen: Set<string>;
  onToggleGroup: (id: string) => void;
  onToggleResult: (id: string) => void;
}) {
  const toolCount = item.invocations.filter((entry) => entry.useMessage?.role === "tool_use").length || item.invocations.length;
  const first = item.messages[0];
  const last = item.messages[item.messages.length - 1];

  return (
    <div className="flex justify-start">
      <div className="mr-auto w-full max-w-[88%] border-l border-[rgba(148,163,184,.35)] pl-4 text-slate-600">
        <button
          type="button"
          onClick={() => onToggleGroup(item.id)}
          className="group inline-flex max-w-full items-center gap-2 rounded-full px-1 py-1 text-left text-sm text-slate-500 transition hover:text-slate-800"
        >
          {groupOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <Terminal className="h-4 w-4" />
          <span>已运行 {toolCount} 个工具</span>
          <span className="truncate text-xs text-slate-400">{formatTimestamp(first?.created_at)} - {formatTimestamp(last?.created_at)}</span>
        </button>

        {groupOpen ? (
          <div className="mt-2 space-y-2">
            {item.invocations.map((invocation) => {
              const open = resultOpen.has(invocation.id);
              const hasResult = Boolean(invocation.resultText.trim());
              return (
                <div key={invocation.id} className="rounded-xl border border-slate-200/80 bg-white/72 px-3 py-2 shadow-sm">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                        <span className="rounded-md bg-slate-100 px-2 py-0.5 font-medium text-slate-700">{invocation.toolName}</span>
                        {invocation.status ? <span>{invocation.status}</span> : null}
                        {typeof invocation.durationMs === "number" ? <span>{invocation.durationMs}ms</span> : null}
                      </div>
                      <div className="mt-1 truncate font-mono text-xs text-slate-700">{compactText(invocation.commandText || invocation.inputText || invocation.resultText)}</div>
                      {invocation.inputText ? (
                        <pre className="mt-2 max-h-28 overflow-auto rounded-lg bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600">{invocation.inputText}</pre>
                      ) : null}
                    </div>
                    {hasResult ? (
                      <button
                        type="button"
                        onClick={() => onToggleResult(invocation.id)}
                        className="shrink-0 rounded-full px-2 py-1 text-xs text-slate-500 transition hover:bg-slate-100 hover:text-slate-800"
                      >
                        {open ? "收起结果" : "查看结果"}
                      </button>
                    ) : null}
                  </div>
                  {open && hasResult ? (
                    <pre className="mt-3 max-h-80 overflow-auto rounded-xl bg-[rgb(18,24,22)] p-4 text-xs leading-5 text-[rgb(231,243,236)]">{invocation.resultText}</pre>
                  ) : null}
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function AuditTimeline({
  messages,
  isStreaming,
  isAutoCompacting,
  streamError,
  footer,
  onStopStreaming,
  activeStreamingMessageId,
}: {
  messages: AuditSessionMessage[];
  isStreaming?: boolean;
  isAutoCompacting?: boolean;
  streamError?: string | null;
  footer?: React.ReactNode;
  onStopStreaming?: () => void;
  activeStreamingMessageId?: string | null;
}) {
  const renderedItems = useMemo(() => buildTimelineItems(messages), [messages]);
  const [openToolGroups, setOpenToolGroups] = useState<Set<string>>(() => new Set());
  const [openToolResults, setOpenToolResults] = useState<Set<string>>(() => new Set());
  const [expandedLongMessages, setExpandedLongMessages] = useState<Set<string>>(() => new Set());

  const toggleToolGroup = (id: string) => {
    setOpenToolGroups((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleToolResult = (id: string) => {
    setOpenToolResults((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleLongMessage = (id: string) => {
    setExpandedLongMessages((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <Card className="flex h-full overflow-hidden rounded-[34px] border border-[#dce5df] bg-white shadow-[0_32px_90px_rgba(54,68,60,0.10)]">
      <div className="flex min-h-0 flex-1 flex-col">
      <CardHeader className="border-b border-[#e7ece9] bg-[linear-gradient(180deg,#ffffff,#fafcfb)] pb-5">
        <div className="flex items-center justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <span className="mt-0.5 flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-[#dce8e1] bg-[linear-gradient(135deg,#ffffff,#eff6f2)] text-[#5f8069] shadow-sm">
              <Bot className="h-5 w-5" />
            </span>
            <div className="min-w-0">
              <CardTitle className="text-2xl font-semibold tracking-tight text-slate-950">审计会话</CardTitle>
              <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">将审计流程作为会话上下文后，可围绕流程步骤、漏洞发现、利用方式、部署验证等内容继续灵活提问。</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="rounded-full border border-[#e0e8e3] bg-white px-4 py-2 text-xs text-slate-600 shadow-sm">
              {isAutoCompacting ? "正在自动压缩上下文..." : isStreaming ? "正在生成回复..." : `共 ${messages.length} 条会话消息`}
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
      <CardContent className="flex min-h-0 flex-1 flex-col p-0">
        <div className="relative m-4 min-h-0 flex-1 overflow-hidden rounded-[30px] border border-[#edf1ef] bg-[linear-gradient(180deg,rgba(255,255,255,.98),rgba(248,250,248,.96))] shadow-inner">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(99,125,108,.035)_1px,transparent_1px),linear-gradient(90deg,rgba(99,125,108,.035)_1px,transparent_1px)] bg-[size:28px_28px]" />
          <div className="relative h-full space-y-5 overflow-y-auto px-5 py-6 sm:px-7">
            {renderedItems.length === 0 ? (
              <div className="flex min-h-[320px] items-center justify-center">
                <div className="max-w-md rounded-[28px] border border-dashed border-[#dfe7e3] bg-white px-8 py-10 text-center shadow-[0_20px_50px_rgba(54,68,60,.06)]">
                  <Bot className="mx-auto mb-4 h-10 w-10 text-[#5f8069]" />
                  <p className="text-base font-medium text-slate-800">会话还没有消息</p>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">审计过程消息、工具调用结果和后续追问都会在这里按聊天形式显示。</p>
                </div>
              </div>
            ) : (
              renderedItems.map((item) => {
                if (item.type === "tool_group") {
                  return (
                    <ToolGroupBlock
                      key={item.id}
                      item={item}
                      groupOpen={openToolGroups.has(item.id)}
                      resultOpen={openToolResults}
                      onToggleGroup={toggleToolGroup}
                      onToggleResult={toggleToolResult}
                    />
                  );
                }
                const message = item.message;
                const presentation = rolePresentation(message);
                const Icon = presentation.icon;
                const isActiveStreamingAssistant = Boolean(
                  isStreaming && message.id === activeStreamingMessageId && message.role === "assistant",
                );
                const reasoningContent = reasoningContentFrom(message);
                const emptyStreaming = isActiveStreamingAssistant && !message.content.trim() && !reasoningContent;
                const shouldCollapseLongMessage = message.role === "user" && isLongUserMessage(message.content);
                const longMessageExpanded = expandedLongMessages.has(message.id);
                const longMessageCollapsed = shouldCollapseLongMessage && !longMessageExpanded;

                return (
                  <div key={message.id} className={`flex ${presentation.align}`}>
                    <div className={`${presentation.bubble} w-full px-5 py-4 sm:px-6`}>
                      <div className="mb-3 flex items-center justify-between gap-4 text-xs">
                        <div className="flex items-center gap-2 font-medium text-slate-500">
                          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-white/90 shadow-sm ring-1 ring-[rgba(180,194,187,.45)]">
                            <Icon className="h-4 w-4" />
                          </span>
                          <span>{presentation.label}</span>
                          {formatSequence(message.sequence) ? (
                            <span className="rounded-full bg-white/80 px-2 py-1 text-[11px] text-slate-400">#{formatSequence(message.sequence)}</span>
                          ) : null}
                        </div>
                        <span className="text-[11px] text-slate-400">{formatTimestamp(message.created_at)}</span>
                      </div>
                      {emptyStreaming ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[#6fa27b]" />
                          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[#8fb99a] [animation-delay:120ms]" />
                          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[#b9d8c0] [animation-delay:240ms]" />
                      <span className="ml-2">
                        {isAutoCompacting
                          ? "正在自动压缩上下文，请稍候..."
                          : "正在组织回答..."}
                      </span>
                        </div>
                      ) : (
                        <div className="relative">
                          {reasoningContent ? (
                            <details
                              defaultOpen
                              className="mb-3 rounded-2xl border border-[#e0e8e3] bg-[#f7fbf8] px-4 py-3 text-sm text-slate-600"
                            >
                              <summary className="cursor-pointer select-none font-medium text-[#6fa27b]">
                                {isActiveStreamingAssistant ? "正在思考" : "模型思考"}
                              </summary>
                              <div className="mt-2 whitespace-pre-wrap break-words font-mono text-xs leading-5 text-slate-500">
                                {reasoningContent}
                              </div>
                            </details>
                          ) : null}
                          <div className={`relative ${longMessageCollapsed ? "max-h-[360px] overflow-hidden" : ""}`}>
                            <div
                              className="audit-markdown max-w-none whitespace-pre-wrap break-words text-[15px] leading-7 text-slate-800 [&_a]:text-[#5f8069] [&_a]:underline [&_blockquote]:border-l-4 [&_blockquote]:border-[#cbdccf] [&_blockquote]:pl-4 [&_code]:rounded-md [&_code]:bg-[rgba(27,31,35,.06)] [&_code]:px-1.5 [&_code]:py-0.5 [&_pre]:overflow-x-auto [&_pre]:rounded-2xl [&_pre]:bg-[rgb(18,24,22)] [&_pre]:p-4 [&_pre]:text-[rgb(231,243,236)] [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_table]:w-full [&_table]:border-collapse [&_td]:border [&_td]:border-[#d8e3db] [&_td]:px-3 [&_td]:py-2 [&_th]:border [&_th]:border-[#d8e3db] [&_th]:bg-[#f4f8f5] [&_th]:px-3 [&_th]:py-2 [&_ul]:list-disc [&_ul]:pl-6 [&_ol]:list-decimal [&_ol]:pl-6"
                              dangerouslySetInnerHTML={renderMarkdown(message.content)}
                            />
                            {longMessageCollapsed ? (
                              <div className="pointer-events-none absolute inset-x-0 bottom-0 h-16 bg-gradient-to-t from-[#edf6ef] to-transparent" />
                            ) : null}
                          </div>
                          {shouldCollapseLongMessage ? (
                            <button
                              type="button"
                              onClick={() => toggleLongMessage(message.id)}
                              className="mt-3 inline-flex items-center gap-1.5 rounded-full px-1 py-1 text-sm font-medium text-[#5f8069] transition hover:text-[#3f5e45]"
                            >
                              {longMessageExpanded ? "收起" : "显示更多"}
                              {longMessageExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                            </button>
                          ) : null}
                          {isActiveStreamingAssistant ? (
                            <span className="ml-1 inline-flex h-6 w-[3px] animate-pulse rounded-full bg-[linear-gradient(180deg,#6fa27b,#b9d8c0)] align-middle shadow-[0_0_12px_rgba(111,162,123,.35)]" />
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
        {footer ? <div className="border-t border-[#e7ece9] bg-[linear-gradient(180deg,#ffffff,#fafcfb)] p-5 sm:p-6">{footer}</div> : null}
      </CardContent>
      </div>
    </Card>
  );
}
