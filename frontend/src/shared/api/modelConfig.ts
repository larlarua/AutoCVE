import { apiClient } from './serverClient';

export type AgentType = 'orchestrator' | 'recon' | 'scan' | 'triage' | 'finding' | 'verification';
export type WorkflowAgentKey = AgentType;

export interface WorkflowAgentState {
  enabled: boolean;
  locked?: boolean;
}

export interface WorkflowConfig {
  agentStates: Record<WorkflowAgentKey, WorkflowAgentState>;
}

export interface AgentModelConfig {
  enabled: boolean;
  llmProvider?: string;
  llmApiKey?: string;
  llmModel?: string;
  llmBaseUrl?: string;
  llmTimeout?: number | null;
  llmTemperature?: number | null;
  llmMaxTokens?: number | null;
  maxIterations?: number | null;
  env?: Record<string, string>;
  alwaysThinkingEnabled?: boolean;
}

export interface ModelProfileConfig {
  id: string;
  name: string;
  llmProvider?: string;
  llmApiKey?: string;
  llmModel?: string;
  llmBaseUrl?: string;
  llmTimeout?: number | null;
  llmTemperature?: number | null;
  llmMaxTokens?: number | null;
  env?: Record<string, string>;
}

export interface UserModelConfigResponse {
  id: string;
  user_id: string;
  llmConfig: Record<string, any>;
  otherConfig: Record<string, any>;
  created_at: string;
  updated_at?: string;
}

export interface ProviderOption {
  value: string;
  label: string;
  default_model: string;
  models: string[];
}

export interface AgentModelTestResponse {
  success: boolean;
  agent_type: AgentType;
  provider?: string;
  model?: string;
  conversation_count?: number;
  response?: string;
  message?: string;
  loaded_skills?: Array<{ name: string; slug: string; description?: string }>;
  matched_skills?: Array<{ name: string; slug: string }>;
}

export interface AgentChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface SyncAssetsResponse {
  skills_synced: number;
  templates_synced: number;
  skill_library: string;
  report_template_library: string;
}

export async function getModelConfig(): Promise<UserModelConfigResponse> {
  const response = await apiClient.get('/config/me');
  return response.data;
}

export async function saveModelConfig(payload: { llmConfig?: Record<string, any>; otherConfig?: Record<string, any> }): Promise<UserModelConfigResponse> {
  const response = await apiClient.put('/config/me', payload);
  return response.data;
}

export async function resetModelConfig(): Promise<void> {
  await apiClient.delete('/config/me');
}

export async function getModelProviders(): Promise<{ providers: ProviderOption[]; agents: AgentType[] }> {
  const response = await apiClient.get('/config/llm-providers');
  return response.data;
}

export async function testGlobalModel(payload: { provider: string; apiKey?: string; model?: string; baseUrl?: string; prompt?: string }) {
  const response = await apiClient.post('/config/test-llm', payload);
  return response.data;
}

export async function testAgentModel(payload: {
  agent_type: AgentType;
  prompt: string;
  include_skills?: boolean;
  agent_model_config?: AgentModelConfig;
  messages?: AgentChatMessage[];
}) {
  const response = await apiClient.post('/config/test-agent-model', payload);
  return response.data as AgentModelTestResponse;
}

export async function syncLocalLibraries() {
  const response = await apiClient.post('/config/sync-assets');
  return response.data as SyncAssetsResponse;
}
