import { apiClient } from "./serverClient";
import type { ManagedVulnerability } from "./vulnerabilities";

export interface AuditSessionMessage {
  id: string;
  session_id: string;
  sequence: number;
  role: string;
  content: string;
  name?: string | null;
  metadata: Record<string, unknown>;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AuditSessionToolCall {
  id: string;
  session_id: string;
  turn_id: string;
  sequence: number;
  tool_use_id: string;
  tool_name: string;
  status: string;
  is_concurrency_safe: boolean;
  input_payload: Record<string, unknown>;
  output_payload: Record<string, unknown>;
  error_message?: string | null;
  duration_ms?: number | null;
  started_at: string;
  completed_at?: string | null;
}

export interface AuditSessionSkill {
  id: string;
  session_id: string;
  skill_ref: string;
  name: string;
  description?: string | null;
  source_type?: string | null;
  enabled: boolean;
  matched: boolean;
  skill_metadata: Record<string, unknown>;
  created_at: string;
}

export interface AuditSessionSkillInvocation {
  id: string;
  session_id: string;
  turn_id: string;
  sequence: number;
  skill_ref: string;
  status: string;
  input_payload: Record<string, unknown>;
  output_payload: Record<string, unknown>;
  error_message?: string | null;
  created_at: string;
}

export interface AuditSessionMemory {
  id: string;
  session_id: string;
  sequence: number;
  memory_kind: string;
  title: string;
  source_type: string;
  source_ref: string;
  content: string;
  relevance_score?: number | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
}

export interface AuditSessionHandoff {
  id: string;
  session_id: string;
  target: string;
  status: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AuditSessionDetail {
  id: string;
  project_id: string;
  task_id?: string | null;
  runtime_stack: string;
  state: string;
  system_prompt?: string | null;
  recon_payload?: Record<string, unknown> | null;
  guardrails_enabled?: boolean;
  created_at: string;
  updated_at: string;
}

export type AuditSessionMessageMode = "chat" | "generate_report_and_sync";

export interface AuditSessionMessageMutationResponse extends AuditSessionMessage {
  mode: AuditSessionMessageMode;
  synced_managed_vulnerability?: ManagedVulnerability | null;
}

export interface AuditSessionStreamEvent {
  type: "session_created" | "user_message" | "assistant_start" | "token" | "done" | "error" | "llm_retry";
  session_id?: string;
  project_id?: string;
  message?: AuditSessionMessage;
  content?: string;
  accumulated?: string;
  usage?: Record<string, unknown>;
  message_text?: string;
  attempt?: number;
  max_attempts?: number;
  error_type?: string;
  mode?: AuditSessionMessageMode;
  synced_managed_vulnerability?: ManagedVulnerability | null;
}

export interface AuditSessionStreamResult {
  mode: AuditSessionMessageMode;
  synced_managed_vulnerability?: ManagedVulnerability | null;
}

export async function getAuditSession(sessionId: string): Promise<AuditSessionDetail> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}`);
  return response.data;
}

export async function getAuditSessionMessages(sessionId: string): Promise<AuditSessionMessage[]> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}/messages`);
  return response.data;
}

export async function getAuditSessionToolCalls(sessionId: string): Promise<AuditSessionToolCall[]> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}/tool-calls`);
  return response.data;
}

export async function getAuditSessionSkills(sessionId: string): Promise<AuditSessionSkill[]> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}/skills`);
  return response.data;
}

export async function getAuditSessionSkillInvocations(sessionId: string): Promise<AuditSessionSkillInvocation[]> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}/skill-invocations`);
  return response.data;
}

export async function getAuditSessionMemories(sessionId: string): Promise<AuditSessionMemory[]> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}/memories`);
  return response.data;
}

export async function getAuditSessionHandoffs(sessionId: string): Promise<AuditSessionHandoff[]> {
  const response = await apiClient.get(`/audit-sessions/${sessionId}/handoffs`);
  return response.data;
}

export async function postAuditSessionMessage(
  sessionId: string,
  content: string,
  mode: AuditSessionMessageMode = "chat",
): Promise<AuditSessionMessageMutationResponse> {
  const response = await apiClient.post(`/audit-sessions/${sessionId}/messages`, { content, mode });
  return response.data;
}

function getAccessToken(): string | null {
  return localStorage.getItem("access_token") || sessionStorage.getItem("access_token");
}

function parseSseChunk(buffer: string): { events: AuditSessionStreamEvent[]; remaining: string } {
  const parts = buffer.split("\n\n");
  const remaining = parts.pop() ?? "";
  const events: AuditSessionStreamEvent[] = [];

  for (const part of parts) {
    const dataLines = part
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim());
    if (dataLines.length === 0) {
      continue;
    }
    try {
      events.push(JSON.parse(dataLines.join("\n")) as AuditSessionStreamEvent);
    } catch (error) {
      console.error("[AuditSessionStream] Failed to parse SSE event", error, dataLines);
    }
  }

  return { events, remaining };
}

export async function streamAuditSessionMessage(
  sessionId: string,
  content: string,
  mode: AuditSessionMessageMode = "chat",
  handlers: {
    onEvent?: (event: AuditSessionStreamEvent) => void;
    signal?: AbortSignal;
  } = {},
): Promise<AuditSessionStreamResult> {
  const token = getAccessToken();
  if (!token) {
    throw new Error("Not authenticated");
  }

  const response = await fetch(`/api/v1/audit-sessions/${sessionId}/messages/stream`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "text/event-stream",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content, mode }),
    signal: handlers.signal,
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("Unable to read stream body");
  }

  const decoder = new TextDecoder();
  let buffer = "";
  let streamResult: AuditSessionStreamResult = { mode };

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });
    const parsed = parseSseChunk(buffer);
    buffer = parsed.remaining;

    for (const event of parsed.events) {
      handlers.onEvent?.(event);
      if (event.type === "error") {
        throw new Error(event.message_text || "Streaming failed");
      }
      if (event.type === "done") {
        streamResult = {
          mode: event.mode || mode,
          synced_managed_vulnerability: event.synced_managed_vulnerability ?? null,
        };
      }
    }
  }

  return streamResult;
}
