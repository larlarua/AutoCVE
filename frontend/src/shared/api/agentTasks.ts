/**
 * Agent Tasks API
 * Agent 瀹¤浠诲姟鐩稿叧鐨?API 璋冪敤
 */

import { apiClient } from "./serverClient";

// ============ Types ============

export interface AgentTask {
  id: string;
  project_id: string;
  name: string | null;
  description: string | null;
  task_type: string;
  status: string;
  current_phase: string | null;
  current_step: string | null;
  version_label?: string | null;
  version_tag?: string | null;
  branch_name?: string | null;
  commit_sha?: string | null;
  repository_url_snapshot?: string | null;
  runtime_session_id?: string | null;
  finding_runtime_stack?: string | null;

  // 缁熻
  total_files: number;
  indexed_files: number;
  analyzed_files: number;
  files_with_findings: number;  // 鏈夋紡娲炲彂鐜扮殑鏂囦欢鏁?
  total_chunks: number;
  findings_count: number;
  verified_count: number;
  false_positive_count: number;

  // Agent 缁熻
  total_iterations: number;
  tool_calls_count: number;
  tokens_used: number;

  // 涓ラ噸绋嬪害缁熻
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;

  // 璇勫垎
  quality_score: number;
  security_score: number | null;

  // 鏃堕棿
  created_at: string;
  started_at: string | null;
  completed_at: string | null;

  // 杩涘害
  progress_percentage: number;

  // 閰嶇疆
  audit_scope: Record<string, unknown> | null;
  target_vulnerabilities: string[] | null;
  verification_level: string | null;
  exclude_patterns: string[] | null;
  target_files: string[] | null;

  // 閿欒淇℃伅
  error_message: string | null;
  finding_outcome?: "none" | "finalized" | "recovered_only" | "incomplete";
  runtime_completion_mode?: string | null;
  finalized_findings_count?: number;
  recovered_candidates_count?: number;
  handoff_ready?: boolean;
  recovered_candidates?: RecoveredCandidate[];
}

export interface RecoveredCandidate {
  title: string;
  severity: string;
  vulnerability_type: string;
  description?: string | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  report_status?: string | null;
  verdict?: string | null;
  origin?: string | null;
  evidence_type?: string | null;
  not_finalized?: boolean;
  source?: string | null;
  sink?: string | null;
  impact?: string | null;
  cve_justification?: string | null;
  verification_notes?: string | null;
  exploit_chain?: Array<{
    step?: number;
    location?: string;
    description?: string;
    data_state?: string;
    bypass_reason?: string;
  }>;
  references?: string[];
  evidence_gaps?: string[];
}

export interface AgentFinding {
  id: string;
  task_id: string;
  vulnerability_type: string;
  severity: string;
  title: string;
  description: string | null;

  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  code_snippet: string | null;

  status: string;
  is_verified: boolean;
  confidence?: number | null;
  report_status?: string | null;
  verdict?: string | null;
  has_poc: boolean;
  poc_code: string | null;
  poc?: {
    description?: string;
    steps?: Array<{
      step?: number;
      action?: string;
      request?: string;
      expected_response?: string;
    }>;
    payload?: string;
    impact?: string;
    cve_justification?: string;
  } | null;

  suggestion: string | null;
  fix_code: string | null;
  ai_explanation: string | null;
  ai_confidence: number | null;
  source?: string | null;
  sink?: string | null;
  exploit_chain?: Array<{
    step?: number;
    location?: string;
    description?: string;
    data_state?: string;
    bypass_reason?: string;
  }>;
  impact?: string | null;
  cve_justification?: string | null;
  verification_notes?: string | null;
  references?: string[];
  origin?: string | null;
  evidence_type?: string | null;
  entry_point_refs?: string[];
  priority_path_refs?: string[];
  business_flow_notes?: string[];
  evidence_gaps?: string[];

  created_at: string;
}

export interface AgentEvent {
  id: string;
  task_id: string;
  event_type: string;
  phase: string | null;
  message: string | null;
  tool_name: string | null;
  tool_input?: Record<string, unknown>;
  tool_output?: Record<string, unknown>;
  tool_duration_ms: number | null;
  finding_id: string | null;
  tokens_used?: number;
  metadata?: Record<string, unknown>;
  sequence: number;
  timestamp: string;
}

export interface CreateAgentTaskRequest {
  project_id: string;
  name?: string;
  description?: string;
  audit_scope?: Record<string, unknown>;
  target_vulnerabilities?: string[];
  verification_level?: "analysis_only" | "sandbox" | "generate_poc";
  version_label: string;
  version_tag?: string;
  branch_name?: string;
  exclude_patterns?: string[];
  target_files?: string[];
  max_iterations?: number;
  token_budget?: number;
  timeout_seconds?: number;
  finding_runtime_stack?: "legacy" | "runtime";
}

export interface AgentTaskSummary {
  task_id: string;
  status: string;
  progress_percentage: number;
  security_score: number;
  quality_score: number;
  statistics: {
    total_files: number;
    indexed_files: number;
    analyzed_files: number;
    files_with_findings: number;
    total_chunks: number;
    findings_count: number;
    verified_count: number;
    false_positive_count: number;
  };
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  vulnerability_types: Record<string, { total: number; verified: number }>;
  duration_seconds: number | null;
}

// ============ API Functions ============

/**
 * 鍒涘缓 Agent 瀹¤浠诲姟
 */
export async function createAgentTask(data: CreateAgentTaskRequest): Promise<AgentTask> {
  const response = await apiClient.post("/agent-tasks/", data);
  return response.data;
}

/**
 * 鑾峰彇 Agent 浠诲姟鍒楄〃
 */
export async function getAgentTasks(params?: {
  project_id?: string;
  status?: string;
  skip?: number;
  limit?: number;
}): Promise<AgentTask[]> {
  const response = await apiClient.get("/agent-tasks/", { params });
  return response.data;
}

/**
 * 鑾峰彇 Agent 浠诲姟璇︽儏
 */
export async function getAgentTask(taskId: string): Promise<AgentTask> {
  const response = await apiClient.get(`/agent-tasks/${taskId}`);
  return response.data;
}

/**
 * 鍚姩 Agent 浠诲姟
 */
export async function startAgentTask(taskId: string): Promise<{ message: string; task_id: string }> {
  const response = await apiClient.post(`/agent-tasks/${taskId}/start`);
  return response.data;
}

/**
 * 鍙栨秷 Agent 浠诲姟
 */
export async function cancelAgentTask(taskId: string): Promise<{ message: string; task_id: string }> {
  const response = await apiClient.post(`/agent-tasks/${taskId}/cancel`);
  return response.data;
}

/**
 * 鑾峰彇 Agent 浠诲姟浜嬩欢鍒楄〃
 */
export async function getAgentEvents(
  taskId: string,
  params?: { after_sequence?: number; limit?: number }
): Promise<AgentEvent[]> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/events/list`, { params });
  return response.data;
}

/**
 * 鑾峰彇 Agent 浠诲姟鍙戠幇鍒楄〃
 */
export async function getAgentFindings(
  taskId: string,
  params?: {
    severity?: string;
    vulnerability_type?: string;
    is_verified?: boolean;
  }
): Promise<AgentFinding[]> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/findings`, { params });
  return response.data;
}

/**
 * 鑾峰彇鍗曚釜鍙戠幇璇︽儏
 */
export async function getAgentFinding(taskId: string, findingId: string): Promise<AgentFinding> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/findings/${findingId}`);
  return response.data;
}

/**
 * 鏇存柊鍙戠幇鐘舵€?
 */
export async function updateAgentFinding(
  taskId: string,
  findingId: string,
  data: { status?: string }
): Promise<AgentFinding> {
  const response = await apiClient.patch(`/agent-tasks/${taskId}/findings/${findingId}`, data);
  return response.data;
}

/**
 * 鑾峰彇浠诲姟鎽樿
 */
export async function getAgentTaskSummary(taskId: string): Promise<AgentTaskSummary> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/summary`);
  return response.data;
}

/**
 * 鍒涘缓 SSE 浜嬩欢婧?
 */
export function createAgentEventSource(taskId: string, afterSequence = 0): EventSource {
  const baseUrl = import.meta.env.VITE_API_URL || "";
  const url = `${baseUrl}/api/v1/agent-tasks/${taskId}/events?after_sequence=${afterSequence}`;

  // 娉ㄦ剰锛欵ventSource 涓嶆敮鎸佽嚜瀹氫箟 headers锛岄渶瑕侀€氳繃 URL 鍙傛暟鎴?cookie 浼犻€掕璇?
  // 濡傛灉闇€瑕佽璇侊紝鍙互鑰冭檻浣跨敤 fetch + ReadableStream 鏇夸唬
  return new EventSource(url, { withCredentials: true });
}

/**
 * 浣跨敤 fetch 娴佸紡鑾峰彇浜嬩欢锛堟敮鎸佽嚜瀹氫箟 headers锛?
 */
export async function* streamAgentEvents(
  taskId: string,
  afterSequence = 0,
  signal?: AbortSignal
): AsyncGenerator<AgentEvent, void, unknown> {
  const token = localStorage.getItem("access_token") || sessionStorage.getItem("access_token");
  const baseUrl = import.meta.env.VITE_API_URL || "";
  const url = `${baseUrl}/api/v1/agent-tasks/${taskId}/events?after_sequence=${afterSequence}`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "text/event-stream",
    },
    signal,
  });

  if (!response.ok) {
    throw new Error(`Failed to connect to event stream: ${response.statusText}`);
  }

  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("No response body");
  }

  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      buffer += decoder.decode(value, { stream: true });

      // 瑙ｆ瀽 SSE 鏍煎紡
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          try {
            const event = JSON.parse(data) as AgentEvent;
            yield event;
          } catch {
            // 蹇界暐瑙ｆ瀽閿欒
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

// ============ Agent Tree Types ============

export interface AgentTreeNode {
  id: string;
  agent_id: string;
  agent_name: string;
  agent_type: string;
  parent_agent_id: string | null;
  depth: number;
  task_description: string | null;
  knowledge_modules: string[] | null;
  status: "created" | "running" | "completed" | "failed" | "waiting";
  result_summary: string | null;
  findings_count: number;
  iterations: number;
  tokens_used: number;
  tool_calls: number;
  duration_ms: number | null;
  children: AgentTreeNode[];
}

export interface AgentTreeResponse {
  task_id: string;
  root_agent_id: string | null;
  total_agents: number;
  running_agents: number;
  completed_agents: number;
  failed_agents: number;
  total_findings: number;
  nodes: AgentTreeNode[];
}

export interface AgentCheckpoint {
  id: string;
  agent_id: string;
  agent_name: string;
  agent_type: string;
  iteration: number;
  status: string;
  total_tokens: number;
  tool_calls: number;
  findings_count: number;
  checkpoint_type: "auto" | "manual" | "error" | "final";
  checkpoint_name: string | null;
  created_at: string | null;
}

export interface CheckpointDetail extends AgentCheckpoint {
  task_id: string;
  parent_agent_id: string | null;
  state_data: Record<string, unknown>;
  metadata: Record<string, unknown> | null;
}

// ============ Agent Tree API Functions ============

/**
 * 鑾峰彇浠诲姟鐨?Agent 鏍戠粨鏋?
 */
export async function getAgentTree(taskId: string): Promise<AgentTreeResponse> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/agent-tree`);
  return response.data;
}

/**
 * 鑾峰彇浠诲姟鐨勬鏌ョ偣鍒楄〃
 */
export async function getAgentCheckpoints(
  taskId: string,
  params?: { agent_id?: string; limit?: number }
): Promise<AgentCheckpoint[]> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/checkpoints`, { params });
  return response.data;
}

/**
 * 鑾峰彇妫€鏌ョ偣璇︽儏
 */
export async function getCheckpointDetail(
  taskId: string,
  checkpointId: string
): Promise<CheckpointDetail> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/checkpoints/${checkpointId}`);
  return response.data;
}


/**
 * 涓嬭浇 Agent 浠诲姟鎶ュ憡
 */
export async function downloadAgentReport(taskId: string, format: "markdown" | "json" | "html" = "markdown", templateId?: string): Promise<void> {
  const response = await apiClient.get(`/agent-tasks/${taskId}/report`, {
    params: { format, template_id: templateId },
    responseType: 'blob',
  });

  // Create download link
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;

  // Calculate filename
  let filename = `audit-report-${taskId.slice(0, 8)}.md`;
  if (format === 'json') {
    filename = `audit-report-${taskId.slice(0, 8)}.json`;
  }
  if (format === 'html') {
    filename = `audit-report-${taskId.slice(0, 8)}.html`;
  }

  // Try to get filename from header
  const contentDisposition = response.headers['content-disposition'];
  if (contentDisposition) {
    const match = contentDisposition.match(/filename=(.+)/);
    if (match && match[1]) filename = match[1].replace(/['"]/g, ''); // Remove quotes if present
  }

  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.parentNode?.removeChild(link);
  window.URL.revokeObjectURL(url);
}


