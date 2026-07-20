import { useCallback, useEffect, useRef, useState } from "react";

import {
  streamAuditSessionMessage,
  type AuditSessionMessage,
  type AuditSessionMessageMode,
  type AuditSessionStreamEvent,
  type AuditSessionStreamResult,
} from "@/shared/api/auditSessions";

function upsertMessage(messages: AuditSessionMessage[], nextMessage: AuditSessionMessage): AuditSessionMessage[] {
  const index = messages.findIndex((message) => message.id === nextMessage.id);
  if (index === -1) {
    return [...messages, nextMessage].sort((left, right) => left.sequence - right.sequence);
  }
  const clone = [...messages];
  clone[index] = nextMessage;
  return clone;
}

function buildThinkingMessage(source: AuditSessionMessage): AuditSessionMessage {
  return {
    id: `thinking-${source.id}`,
    session_id: source.session_id,
    sequence: source.sequence + 0.01,
    role: "assistant",
    content: "",
    name: null,
    metadata: { kind: "audit_chat_thinking_placeholder", streaming: true },
    payload: {},
    created_at: new Date().toISOString(),
  };
}

export function useAuditSessionChatStream({
  sessionId,
  setMessages,
  refresh,
  streamMessage = streamAuditSessionMessage,
}: {
  sessionId?: string;
  setMessages: React.Dispatch<React.SetStateAction<AuditSessionMessage[]>>;
  refresh: (options?: { silent?: boolean }) => Promise<void>;
  streamMessage?: (
    sessionId: string,
    content: string,
    mode?: AuditSessionMessageMode,
    selectedSkillRefs?: string[],
    handlers?: {
      onEvent?: (event: AuditSessionStreamEvent) => void;
      signal?: AbortSignal;
    },
  ) => Promise<AuditSessionStreamResult>;
}) {
  const [isStreaming, setIsStreaming] = useState(false);
  const [isAutoCompacting, setIsAutoCompacting] = useState(false);
  const [streamError, setStreamError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const streamingAssistantIdRef = useRef<string | null>(null);
  const thinkingAssistantIdRef = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      abortRef.current = null;
      streamingAssistantIdRef.current = null;
      thinkingAssistantIdRef.current = null;
    };
  }, []);

  const clearPlaceholders = useCallback(() => {
    const placeholderIds = new Set([streamingAssistantIdRef.current, thinkingAssistantIdRef.current].filter(Boolean));
    if (placeholderIds.size > 0) {
      setMessages((previous) => previous.filter((message) => !placeholderIds.has(message.id)));
    }
    streamingAssistantIdRef.current = null;
    thinkingAssistantIdRef.current = null;
  }, [setMessages]);

  const handleEvent = useCallback((event: AuditSessionStreamEvent) => {
    if (event.type === "user_message" && event.message) {
      setStreamError(null);
      const thinkingMessage = buildThinkingMessage(event.message);
      thinkingAssistantIdRef.current = thinkingMessage.id;
      streamingAssistantIdRef.current = thinkingMessage.id;
      setMessages((previous) => upsertMessage(previous, event.message!));
      setMessages((previous) => upsertMessage(previous, thinkingMessage));
      return;
    }

    if (event.type === "assistant_start" && event.message) {
      setStreamError(null);
      streamingAssistantIdRef.current = event.message.id;
      const thinkingAssistantId = thinkingAssistantIdRef.current;
      thinkingAssistantIdRef.current = null;
      setMessages((previous) => {
        const withoutThinking = thinkingAssistantId ? previous.filter((message) => message.id !== thinkingAssistantId) : previous;
        return upsertMessage(withoutThinking, event.message!);
      });
      return;
    }

    if (event.type === "message" && event.message) {
      setStreamError(null);
      setMessages((previous) => upsertMessage(previous, event.message!));
      return;
    }

    if (event.type === "heartbeat") {
      return;
    }

    if (event.type === "context_compaction_started") {
      setStreamError(null);
      setIsAutoCompacting(true);
      return;
    }

    if (event.type === "context_compacted" || event.type === "context_compaction_failed") {
      setIsAutoCompacting(false);
      return;
    }

    if (event.type === "token") {
      setStreamError(null);
      const streamingAssistantId = streamingAssistantIdRef.current;
      if (!streamingAssistantId) {
        return;
      }
      setMessages((previous) =>
        previous.map((message) =>
          message.id === streamingAssistantId
            ? {
                ...message,
                content: event.accumulated ?? `${message.content}${event.content ?? ""}`,
              }
            : message,
        ),
      );
      return;
    }

    if (event.type === "reasoning_delta") {
      setStreamError(null);
      let streamingAssistantId = streamingAssistantIdRef.current;
      if (!streamingAssistantId) {
        streamingAssistantId = `thinking-${sessionId || "session"}-${Date.now()}`;
        streamingAssistantIdRef.current = streamingAssistantId;
        thinkingAssistantIdRef.current = streamingAssistantId;
        setMessages((previous) =>
          upsertMessage(previous, {
            id: streamingAssistantId!,
            session_id: sessionId || "",
            sequence: previous.length + 1,
            role: "assistant",
            content: "",
            name: null,
            metadata: { kind: "audit_chat_thinking_placeholder", streaming: true },
            payload: {},
            created_at: new Date().toISOString(),
          }),
        );
      }
      const accumulated = event.accumulated ?? event.reasoning_content ?? event.content ?? "";
      setMessages((previous) =>
        previous.map((message) =>
          message.id === streamingAssistantId
            ? {
                ...message,
                payload: {
                  ...message.payload,
                  reasoning_content: accumulated,
                },
              }
            : message,
        ),
      );
      return;
    }

    if (event.type === "done" && event.message) {
      setStreamError(null);
      const placeholderIds = new Set([streamingAssistantIdRef.current, thinkingAssistantIdRef.current].filter(Boolean));
      setMessages((previous) => {
        const withoutPlaceholder = previous.filter((message) => !placeholderIds.has(message.id));
        return upsertMessage(withoutPlaceholder, event.message!);
      });
      streamingAssistantIdRef.current = null;
      thinkingAssistantIdRef.current = null;
      return;
    }

    if (event.type === "done") {
      setStreamError(null);
      clearPlaceholders();
      return;
    }

    if (event.type === "llm_retry") {
      setStreamError(event.message_text || "模型服务暂时不可用，正在自动重试。");
      return;
    }

    if (event.type === "assistant_tombstone") {
      clearPlaceholders();
      return;
    }

    if (event.type === "error") {
      setStreamError(event.message_text || "Streaming failed");
    }
  }, [clearPlaceholders, sessionId, setMessages]);

  const stopStreaming = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    clearPlaceholders();
    setIsAutoCompacting(false);
    setIsStreaming(false);
    void refresh({ silent: true });
  }, [clearPlaceholders, refresh]);

  const runStreamRequest = useCallback(async <TResult,>(
    runner: (handlers: { onEvent?: (event: AuditSessionStreamEvent) => void; signal?: AbortSignal }) => Promise<TResult>,
  ): Promise<TResult> => {
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    streamingAssistantIdRef.current = null;
    thinkingAssistantIdRef.current = null;
    setIsStreaming(true);
    setIsAutoCompacting(false);
    setStreamError(null);

    try {
      const result = await runner({
        signal: abortRef.current.signal,
        onEvent: handleEvent,
      });
      await refresh({ silent: true });
      return result;
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        setStreamError(error instanceof Error ? error.message : "Streaming failed");
        await refresh({ silent: true });
      }
      throw error;
    } finally {
      setIsStreaming(false);
      setIsAutoCompacting(false);
      abortRef.current = null;
    }
  }, [handleEvent, refresh]);

  const sendMessage = useCallback(async (
    content: string,
    mode: AuditSessionMessageMode = "chat",
    selectedSkillRefs: string[] = [],
  ): Promise<AuditSessionStreamResult> => {
    if (!sessionId) {
      throw new Error("Missing session id");
    }
    return runStreamRequest((handlers) => {
      if (streamMessage === streamAuditSessionMessage) {
        return streamMessage(sessionId, content, mode, selectedSkillRefs, handlers);
      }
      return (streamMessage as unknown as (
        sessionId: string,
        content: string,
        handlers?: {
          onEvent?: (event: AuditSessionStreamEvent) => void;
          signal?: AbortSignal;
        },
      ) => Promise<AuditSessionStreamResult>)(sessionId, content, handlers);
    });
  }, [runStreamRequest, sessionId, streamMessage]);

  return {
    isStreaming,
    isAutoCompacting,
    streamError,
    runStreamRequest,
    sendMessage,
    stopStreaming,
    streamingAssistantId: streamingAssistantIdRef.current,
  };
}
