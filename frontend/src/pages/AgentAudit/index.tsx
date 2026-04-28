/**
 * Agent Audit Page - Modular Implementation
 * Main entry point for the Agent Audit feature
 * Cassette Futurism / Terminal Retro aesthetic
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Terminal, Bot, Loader2, Radio, Filter, Maximize2, FileText } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { useAgentStream } from "@/hooks/useAgentStream";

import {
  getAgentTask,
  getAgentFindings,
  cancelAgentTask,
  getAgentTree,
  getAgentEvents,
  AgentEvent,
} from "@/shared/api/agentTasks";
import {
  getAuditSessionHandoffs,
  getAuditSessionMessages,
} from "@/shared/api/auditSessions";
import type { AuditSessionHandoff, AuditSessionMessage } from "@/pages/AuditSession/types";
import CreateAgentTaskDialog from "@/components/agent/CreateAgentTaskDialog";

// Local imports
import {
  SplashScreen,
  Header,
  LogEntry,
  AgentTreeNodeItem,
  AgentDetailPanel,
  StatsPanel,
  FinalReportPanel,
  AgentErrorBoundary,
} from "./components";
import ReportExportDialog from "./components/ReportExportDialog";
import { useAgentAuditState } from "./hooks";
import { ACTION_VERBS, POLLING_INTERVALS } from "./constants";
import { cleanThinkingContent, truncateOutput, createLogItem } from "./utils";
import type { LogItem } from "./types";

function formatHistoricalLogTime(timestamp?: string | null): string {
  if (!timestamp) {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
  }

  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
  }

  return parsed.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function buildRuntimeSessionLogs(messages: AuditSessionMessage[], handoffs: AuditSessionHandoff[]): LogItem[] {
  const logs: LogItem[] = [];

  const pushLog = (id: string, timestamp: string, item: Omit<LogItem, 'id' | 'time'>) => {
    const created = createLogItem(item);
    logs.push({
      ...created,
      id,
      time: formatHistoricalLogTime(timestamp),
    });
  };

  messages.forEach((message) => {
    const metadata = (message.metadata || {}) as Record<string, unknown>;
    const payload = (message.payload || {}) as Record<string, unknown>;
    const toolName = String(message.name || payload.tool_name || 'unknown');
    const content = message.content || '';

    if (message.role === 'user' && metadata.kind === 'finalization_prompt') {
      return;
    }

    if (message.role === 'tool_use') {
      pushLog(`runtime-msg-${message.id}`, message.created_at, {
        type: 'tool',
        title: `Tool: ${toolName}`,
        content: payload.input ? `Input:\n${JSON.stringify(payload.input, null, 2)}` : undefined,
        tool: { name: toolName, status: 'running' },
        agentName: 'Finding',
      });
      return;
    }

    if (message.role === 'tool_result') {
      pushLog(`runtime-msg-${message.id}`, message.created_at, {
        type: 'tool',
        title: `Completed: ${toolName}`,
        content: content ? `Output:\n${truncateOutput(content)}` : undefined,
        tool: {
          name: toolName,
          duration: Number(metadata.duration_ms || 0),
          status: metadata.is_error ? 'failed' : 'completed',
        },
        agentName: 'Finding',
      });
      return;
    }

    if (message.role === 'assistant') {
      const trimmed = content.trim();
      const isThoughtLike = trimmed.startsWith('Thought:') || trimmed.includes('\nThought:') || trimmed.includes('Tool Call:');
      const isFinalAnswer = /^Final Answer:/i.test(trimmed) || /"findings"\s*:/.test(trimmed);
      pushLog(`runtime-msg-${message.id}`, message.created_at, {
        type: isThoughtLike ? 'thinking' : 'info',
        title: isFinalAnswer ? 'Final Answer' : (trimmed.slice(0, 100) + (trimmed.length > 100 ? '...' : '') || 'Assistant'),
        content: isThoughtLike ? cleanThinkingContent(trimmed) : truncateOutput(trimmed),
        agentName: 'Finding',
      });
      return;
    }

    if (message.role === 'user') {
      pushLog(`runtime-msg-${message.id}`, message.created_at, {
        type: 'user',
        title: message.name === 'runtime_finalizer' ? 'Runtime finalizer' : 'User prompt',
        content: truncateOutput(content),
        agentName: 'Finding',
      });
      return;
    }

    pushLog(`runtime-msg-${message.id}`, message.created_at, {
      type: 'info',
      title: `${message.role}`,
      content: truncateOutput(content),
      agentName: 'Finding',
    });
  });

  handoffs.forEach((handoff) => {
    pushLog(`runtime-handoff-${handoff.id}`, handoff.created_at, {
      type: 'dispatch',
      title: `Handoff to ${handoff.target} (${handoff.status})`,
      content: truncateOutput(JSON.stringify(handoff.payload, null, 2)),
      agentName: 'Finding',
    });
  });

  return logs.sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
}

function AgentAuditPageContent() {
  const navigate = useNavigate();
  const { taskId } = useParams<{ taskId: string }>();
  const {
    task, findings, agentTree, logs, selectedAgentId, showAllLogs,
    isLoading, connectionStatus, expandedLogIds,
    treeNodes, filteredLogs, isRunning, isComplete,
    setTask, setFindings, setAgentTree, addLog, updateLog, removeLog,
    selectAgent, setLoading, setConnectionStatus, toggleLogExpanded,
    setCurrentAgentName, getCurrentAgentName, setCurrentThinkingId, getCurrentThinkingId,
    dispatch, reset,
  } = useAgentAuditState();

  // Local state
  const [showSplash, setShowSplash] = useState(!taskId);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [activeDetailView, setActiveDetailView] = useState<'activity' | 'report'>('activity');
  const [isCancelling, setIsCancelling] = useState(false);
  const [statusVerb, setStatusVerb] = useState(ACTION_VERBS[0]);
  const [statusDots, setStatusDots] = useState(0);

  const agentTreeRefreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastAgentTreeRefreshTime = useRef<number>(0);
  const previousTaskIdRef = useRef<string | undefined>(undefined);
  const disconnectStreamRef = useRef<(() => void) | null>(null);
  const lastEventSequenceRef = useRef<number>(0);
  const hasConnectedRef = useRef<boolean>(false); // 馃敟 杩借釜鏄惁宸茶繛鎺?SSE
  const hasLoadedHistoricalEventsRef = useRef<boolean>(false); // 馃敟 杩借釜鏄惁宸插姞杞藉巻鍙蹭簨浠?
  // 馃敟 浣跨敤 state 鏉ユ爣璁板巻鍙蹭簨浠跺姞杞界姸鎬佸拰瑙﹀彂 streamOptions 閲嶆柊璁＄畻
  const [afterSequence, setAfterSequence] = useState<number>(0);
  const [historicalEventsLoaded, setHistoricalEventsLoaded] = useState<boolean>(false);

  // 馃敟 褰?taskId 鍙樺寲鏃剁珛鍗抽噸缃姸鎬侊紙鏂板缓浠诲姟鏃舵竻鐞嗘棫鏃ュ織锛?
  useEffect(() => {
    // 濡傛灉 taskId 鍙戠敓鍙樺寲锛岀珛鍗抽噸缃?
    if (taskId !== previousTaskIdRef.current) {
      // 1. 鍏堟柇寮€鏃х殑 SSE 娴佽繛鎺?
      if (disconnectStreamRef.current) {
        disconnectStreamRef.current();
        disconnectStreamRef.current = null;
      }
      // 2. 閲嶇疆鎵€鏈夌姸鎬?
      reset();
      setShowSplash(!taskId);
      // 3. 閲嶇疆浜嬩欢搴忓垪鍙峰拰鍔犺浇鐘舵€?
      lastEventSequenceRef.current = 0;
      hasConnectedRef.current = false; // 馃敟 閲嶇疆 SSE 杩炴帴鏍囧織
      hasLoadedHistoricalEventsRef.current = false; // 馃敟 閲嶇疆鍘嗗彶浜嬩欢鍔犺浇鏍囧織
      setHistoricalEventsLoaded(false); // 馃敟 閲嶇疆鍘嗗彶浜嬩欢鍔犺浇鐘舵€?
      setAfterSequence(0); // 馃敟 閲嶇疆 afterSequence state
    }
    previousTaskIdRef.current = taskId;
  }, [taskId, reset]);

  useEffect(() => {
    setActiveDetailView('activity');
  }, [taskId]);

  // ============ Data Loading ============

  const loadTask = useCallback(async () => {
    if (!taskId) return null;
    try {
      const data = await getAgentTask(taskId);
      setTask(data);
      return data;
    } catch {
      toast.error("Failed to load task");
      return null;
    }
  }, [taskId, setTask]);

  const loadFindings = useCallback(async () => {
    if (!taskId) return;
    try {
      const data = await getAgentFindings(taskId);
      setFindings(data);
    } catch (err) {
      console.error(err);
    }
  }, [taskId, setFindings]);

  const loadAgentTree = useCallback(async () => {
    if (!taskId) return;
    try {
      const data = await getAgentTree(taskId);
      setAgentTree(data);
    } catch (err) {
      console.error(err);
    }
  }, [taskId, setAgentTree]);

  const debouncedLoadAgentTree = useCallback(() => {
    const now = Date.now();
    const minInterval = POLLING_INTERVALS.AGENT_TREE_DEBOUNCE;

    if (agentTreeRefreshTimer.current) {
      clearTimeout(agentTreeRefreshTimer.current);
    }

    const timeSinceLastRefresh = now - lastAgentTreeRefreshTime.current;
    if (timeSinceLastRefresh < minInterval) {
      agentTreeRefreshTimer.current = setTimeout(() => {
        lastAgentTreeRefreshTime.current = Date.now();
        loadAgentTree();
      }, minInterval - timeSinceLastRefresh);
    } else {
      agentTreeRefreshTimer.current = setTimeout(() => {
        lastAgentTreeRefreshTime.current = Date.now();
        loadAgentTree();
      }, POLLING_INTERVALS.AGENT_TREE_MIN_DELAY);
    }
  }, [loadAgentTree]);

  const loadRuntimeSessionSnapshot = useCallback(async (runtimeSessionId?: string | null): Promise<LogItem[]> => {
    if (!runtimeSessionId) {
      return [];
    }
    try {
      const [messages, handoffs] = await Promise.all([
        getAuditSessionMessages(runtimeSessionId),
        getAuditSessionHandoffs(runtimeSessionId),
      ]);
      return buildRuntimeSessionLogs(messages, handoffs);
    } catch (error) {
      console.error('[AgentAudit] Failed to load runtime session trace:', error);
      return [];
    }
  }, []);
  const mergeRuntimeSessionLogs = useCallback(async (runtimeSessionId?: string | null) => {
    if (!runtimeSessionId) {
      return 0;
    }
    const runtimeLogs = await loadRuntimeSessionSnapshot(runtimeSessionId);
    if (runtimeLogs.length === 0) {
      return 0;
    }
    const merged = new Map<string, LogItem>();
    logs.forEach((log) => merged.set(log.id, log));
    runtimeLogs.forEach((log) => merged.set(log.id, log));
    const payload = Array.from(merged.values()).sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
    dispatch({ type: 'SET_LOGS', payload });
    return payload.length;
  }, [dispatch, loadRuntimeSessionSnapshot, logs]);

  // 馃敟 NEW: 鍔犺浇鍘嗗彶浜嬩欢骞惰浆鎹负鏃ュ織椤?
  const loadHistoricalEvents = useCallback(async (options?: { forceReload?: boolean }) => {
    if (!taskId) return 0;
    const forceReload = options?.forceReload === true;

    // 馃敟 闃叉閲嶅鍔犺浇鍘嗗彶浜嬩欢
    if (forceReload) {
      hasLoadedHistoricalEventsRef.current = false;
      lastEventSequenceRef.current = 0;
      dispatch({ type: 'SET_LOGS', payload: [] });
    }

    if (hasLoadedHistoricalEventsRef.current && lastEventSequenceRef.current > 0) {
      console.log('[AgentAudit] Historical events already loaded, skipping');
      return lastEventSequenceRef.current;
    }
    hasLoadedHistoricalEventsRef.current = true;

    try {
      console.log(`[AgentAudit] Fetching historical events for task ${taskId}...`);
      const events: AgentEvent[] = [];
      let cursor = 0;
      while (true) {
        const page = await getAgentEvents(taskId, { after_sequence: cursor, limit: 500 });
        if (page.length === 0) break;
        events.push(...page);
        cursor = Math.max(cursor, ...page.map(event => event.sequence));
        if (page.length < 500) break;
      }
      console.log(`[AgentAudit] Received ${events.length} events from API`);

      if (events.length === 0) {
        console.log('[AgentAudit] No historical events found');
        return 0;
      }

      // 鎸?sequence 鎺掑簭纭繚椤哄簭姝ｇ‘
      events.sort((a, b) => a.sequence - b.sequence);

      // 杞崲浜嬩欢涓烘棩蹇楅」
      let processedCount = 0;
      events.forEach((event: AgentEvent) => {
        // 鏇存柊鏈€鍚庣殑浜嬩欢搴忓垪鍙?
        if (event.sequence > lastEventSequenceRef.current) {
          lastEventSequenceRef.current = event.sequence;
        }

        // 鎻愬彇 agent_name
        const agentName = (event.metadata?.agent_name as string) ||
          (event.metadata?.agent as string) ||
          undefined;

        // 鏍规嵁浜嬩欢绫诲瀷鍒涘缓鏃ュ織椤?
        switch (event.event_type) {
          // LLM 鎬濊€冪浉鍏?
          case 'thinking':
          case 'llm_thought':
          case 'llm_start':
          case 'llm_action':
          case 'llm_observation':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'thinking',
                title: event.message?.slice(0, 100) + (event.message && event.message.length > 100 ? '...' : '') || 'Thinking...',
                content: event.message || (event.metadata?.thought as string) || '',
                agentName,
              }
            });
            processedCount++;
            break;

          case 'llm_decision':
          case 'llm_complete':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'info',
                title: event.message?.slice(0, 100) + (event.message && event.message.length > 100 ? '...' : '') || 'Decision',
                content: event.message || '',
                agentName,
              }
            });
            processedCount++;
            break;

          case 'final_answer':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'info',
                title: 'Final Answer',
                content: event.metadata?.result
                  ? truncateOutput(JSON.stringify(event.metadata.result, null, 2))
                  : (event.message || ''),
                agentName,
              }
            });
            processedCount++;
            break;

          // 宸ュ叿璋冪敤鐩稿叧
          case 'tool_call':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'tool',
                title: `Tool: ${event.tool_name || 'unknown'}`,
                content: event.tool_input ? `Input:\n${JSON.stringify(event.tool_input, null, 2)}` : '',
                tool: {
                  name: event.tool_name || 'unknown',
                  status: 'running' as const,
                },
                agentName,
              }
            });
            processedCount++;
            break;

          case 'tool_result':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'tool',
                title: `Completed: ${event.tool_name || 'unknown'}`,
                content: event.tool_output
                  ? `Output:\n${truncateOutput(typeof event.tool_output === 'string' ? event.tool_output : JSON.stringify(event.tool_output, null, 2))}`
                  : '',
                tool: {
                  name: event.tool_name || 'unknown',
                  duration: event.tool_duration_ms || 0,
                  status: 'completed' as const,
                },
                agentName,
              }
            });
            processedCount++;
            break;

          // 鍙戠幇婕忔礊 - 馃敟 鍖呭惈鎵€鏈?finding 鐩稿叧浜嬩欢绫诲瀷
          case 'finding':
          case 'finding_new':
          case 'finding_verified':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'finding',
                title: event.message || (event.metadata?.title as string) || 'Vulnerability found',
                severity: (event.metadata?.severity as string) || 'medium',
                agentName,
              }
            });
            processedCount++;
            break;

          // 璋冨害鍜岄樁娈电浉鍏?
          case 'dispatch':
          case 'dispatch_complete':
          case 'phase_start':
          case 'phase_complete':
          case 'node_start':
          case 'node_complete':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'dispatch',
                title: event.message || `Event: ${event.event_type}`,
                agentName,
              }
            });
            processedCount++;
            break;

          // 浠诲姟瀹屾垚
          case 'task_complete':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'info',
                title: event.message || 'Task completed',
                agentName,
              }
            });
            processedCount++;
            break;

          // 浠诲姟閿欒
          case 'task_error':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'error',
                title: event.message || 'Task error',
                agentName,
              }
            });
            processedCount++;
            break;

          // 浠诲姟鍙栨秷
          case 'task_cancel':
            dispatch({
              type: 'ADD_LOG',
              payload: {
                type: 'info',
                title: event.message || 'Task cancelled',
                agentName,
              }
            });
            processedCount++;
            break;

          // 杩涘害浜嬩欢
          case 'progress':
            if (event.message) {
              dispatch({
                type: 'UPDATE_OR_ADD_PROGRESS_LOG',
                payload: {
                  progressKey: `${agentName || 'task'}_progress`,
                  title: event.message,
                  agentName,
                }
              });
              processedCount++;
            }
            break;

          // 璺宠繃 thinking_token 绛夐珮棰戜簨浠讹紙瀹冧滑涓嶄細琚繚瀛樺埌鏁版嵁搴擄級
          case 'thinking_token':
          case 'thinking_start':
          case 'thinking_end':
            // 杩欎簺浜嬩欢鏄祦寮忎紶杈撶敤鐨勶紝涓嶄繚瀛樺埌鏁版嵁搴?
            break;

          default:
            // 鍏朵粬浜嬩欢绫诲瀷涔熸樉绀轰负 info锛堝鏋滄湁娑堟伅锛?
            if (event.message) {
              dispatch({
                type: 'ADD_LOG',
                payload: {
                  type: 'info',
                  title: event.message,
                  agentName,
                }
              });
              processedCount++;
            }
        }
      });

      console.log(`[AgentAudit] Processed ${processedCount} events into logs, last sequence: ${lastEventSequenceRef.current}`);
      // 馃敟 鏇存柊 afterSequence state锛岃Е鍙?streamOptions 閲嶆柊璁＄畻
      setAfterSequence(lastEventSequenceRef.current);
      return events.length;
    } catch (err) {
      console.error('[AgentAudit] Failed to load historical events:', err);
      hasLoadedHistoricalEventsRef.current = false;
      return 0;
    }
  }, [taskId, dispatch, setAfterSequence, loadRuntimeSessionSnapshot]);

  /*
  const loadHistoricalEventsSnapshot = useCallback(async (runtimeSessionId?: string | null) => {
    if (!taskId) return 0;

    try {
      console.log(`[AgentAudit] Snapshot reloading events for task ${taskId}...`);
      hasLoadedHistoricalEventsRef.current = false;
      lastEventSequenceRef.current = 0;
      dispatch({ type: 'SET_LOGS', payload: [] });
      const events: AgentEvent[] = [];
      let cursor = 0;
      while (true) {
        const page = await getAgentEvents(taskId, { after_sequence: cursor, limit: 500 });
        if (page.length === 0) break;
        events.push(...page);
        cursor = Math.max(cursor, ...page.map((event) => event.sequence));
        if (page.length < 500) break;
      }

      if (events.length === 0) {
        return 0;
      }

      events.sort((a, b) => a.sequence - b.sequence);
      const snapshotLogs: LogItem[] = [];
      const progressIndex = new Map<string, number>();
      const progressPatterns: { pattern: RegExp; key: string }[] = [
        { pattern: /缁便垹绱╂潻娑樺[:閿涙瓥?\s*\d+\/\d+/, key: 'index_progress' },
        { pattern: /瀹撳苯鍙嗘潻娑樺[:閿涙瓥?\s*\d+\/\d+/, key: 'embed_progress' },
        { pattern: /閸忓娈曟潻娑樺[:閿涙瓥?\s*\d+%/, key: 'clone_progress' },
        { pattern: /娑撳娴囨潻娑樺[:閿涙瓥?\s*\d+%/, key: 'download_progress' },
        { pattern: /娑撳﹣绱舵潻娑樺[:閿涙瓥?\s*\d+%/, key: 'upload_progress' },
        { pattern: /閹殿偅寮挎潻娑樺[:閿涙瓥?\s*\d+/, key: 'scan_progress' },
        { pattern: /閸掑棙鐎芥潻娑樺[:閿涙瓥?\s*\d+/, key: 'analyze_progress' },
      ];

      for (const event of events) {
        if (event.sequence > lastEventSequenceRef.current) {
          lastEventSequenceRef.current = event.sequence;
        }

        const eventType = (
          event.event_type ||
          (event as unknown as { type?: string }).type ||
          ''
        ).toString();
        const metadata = (
          event.metadata ||
          (event as unknown as { event_metadata?: Record<string, unknown> }).event_metadata ||
          {}
        ) as Record<string, unknown>;
        const agentName = (metadata.agent_name as string) ||
          (metadata.agent as string) ||
          ((event as unknown as { agent_name?: string }).agent_name) ||
          undefined;

        const pushLog = (item: Omit<LogItem, 'id' | 'time'>) => {
          snapshotLogs.push({
            ...item,
            id: `hist-${event.sequence}-${snapshotLogs.length}`,
            time: formatHistoricalLogTime(event.timestamp),
          });
        };

        const message = event.message || '';
        const upsertProgress = (title: string) => {
          const matched = progressPatterns.find((pattern) => pattern.pattern.test(title));
          if (!matched) {
            pushLog({ type: 'info', title, agentName });
            return;
          }
          const existingIndex = progressIndex.get(matched.key);
          const nextItem: LogItem = {
            id: `hist-progress-${matched.key}`,
            time: formatHistoricalLogTime(event.timestamp),
            type: 'progress',
            title,
            progressKey: matched.key,
            agentName,
          };
          if (existingIndex !== undefined) {
            snapshotLogs[existingIndex] = nextItem;
            return;
          }
          progressIndex.set(matched.key, snapshotLogs.length);
          snapshotLogs.push(nextItem);
        };

        switch (eventType) {
          case 'thinking':
          case 'llm_thought':
            pushLog({
              type: 'thinking',
              title: message.slice(0, 100) + (message.length > 100 ? '...' : '') || 'Thinking...',
              content: message || (metadata.thought as string) || '',
              agentName,
            });
            break;
          case 'llm_decision':
          case 'llm_complete':
            pushLog({
              type: 'info',
              title: message.slice(0, 100) + (message.length > 100 ? '...' : '') || 'Decision',
              content: message,
              agentName,
            });
            break;
          case 'final_answer':
            pushLog({
              type: 'info',
              title: 'Final Answer',
              content: metadata.result ? truncateOutput(JSON.stringify(metadata.result, null, 2)) : message,
              agentName,
            });
            break;
          case 'tool_call':
            pushLog({
              type: 'tool',
              title: `Tool: ${event.tool_name || 'unknown'}`,
              content: event.tool_input ? `Input:\n${JSON.stringify(event.tool_input, null, 2)}` : '',
              tool: { name: event.tool_name || 'unknown', status: 'running' },
              agentName,
            });
            break;
          case 'tool_result':
            pushLog({
              type: 'tool',
              title: `Completed: ${event.tool_name || 'unknown'}`,
              content: event.tool_output
                ? `Output:\n${truncateOutput(typeof event.tool_output === 'string' ? event.tool_output : JSON.stringify(event.tool_output, null, 2))}`
                : '',
              tool: {
                name: event.tool_name || 'unknown',
                duration: event.tool_duration_ms || 0,
                status: 'completed',
              },
              agentName,
            });
            break;
          case 'finding':
          case 'finding_new':
          case 'finding_verified':
            pushLog({
              type: 'finding',
              title: message || (metadata.title as string) || 'Vulnerability found',
              severity: (metadata.severity as string) || 'medium',
              agentName,
            });
            break;
          case 'dispatch':
          case 'dispatch_complete':
          case 'phase_start':
          case 'phase_complete':
          case 'node_start':
          case 'node_complete':
            pushLog({
              type: 'dispatch',
              title: message || `Event: ${eventType}`,
              agentName,
            });
            break;
          case 'progress':
          case 'info':
          case 'complete':
          case 'error':
          case 'warning':
            upsertProgress(message || eventType);
            break;
          case 'thinking_token':
          case 'thinking_start':
          case 'thinking_end':
            break;
          default:
            if (message) {
              pushLog({ type: 'info', title: message, agentName });
            }
        }
      }

      dispatch({ type: 'SET_LOGS', payload: snapshotLogs });
      hasLoadedHistoricalEventsRef.current = true;
      setHistoricalEventsLoaded(true);
      setAfterSequence(lastEventSequenceRef.current);
      console.log(`[AgentAudit] Snapshot loaded ${snapshotLogs.length} logs`);
      return snapshotLogs.length;
    } catch (error) {
      console.error('[AgentAudit] Snapshot reload failed:', error);
      return 0;
    }
  }, [taskId, dispatch, setAfterSequence, loadRuntimeSessionSnapshot]);
  */

  const loadHistoricalEventsSnapshot = useCallback(async (runtimeSessionId?: string | null) => {
    if (!taskId) return 0;

    try {
      console.log(`[AgentAudit] Snapshot reloading events for task ${taskId}...`);
      hasLoadedHistoricalEventsRef.current = false;
      lastEventSequenceRef.current = 0;
      dispatch({ type: 'SET_LOGS', payload: [] });
      setHistoricalEventsLoaded(false);

      const events: AgentEvent[] = [];
      let cursor = 0;
      while (true) {
        const page = await getAgentEvents(taskId, { after_sequence: cursor, limit: 500 });
        if (page.length === 0) break;
        events.push(...page);
        cursor = Math.max(cursor, ...page.map((event) => event.sequence));
        if (page.length < 500) break;
      }

      const runtimeLogs = await loadRuntimeSessionSnapshot(runtimeSessionId);

      if (events.length === 0 && runtimeLogs.length === 0) {
        console.log('[AgentAudit] Snapshot found no historical events');
        setAfterSequence(0);
        return 0;
      }

      events.sort((a, b) => a.sequence - b.sequence);
      const snapshotLogs: LogItem[] = [];
      const progressIndex = new Map<string, number>();

      for (const event of events) {
        lastEventSequenceRef.current = Math.max(lastEventSequenceRef.current, event.sequence);
        const eventType = event.event_type || '';
        const metadata = (event.metadata || {}) as Record<string, unknown>;
        const agentName = (metadata.agent_name as string) || (metadata.agent as string) || undefined;
        const message = event.message || '';

        const pushLog = (item: Omit<LogItem, 'id' | 'time'>) => {
          const created = createLogItem(item);
          snapshotLogs.push({
            ...created,
            id: `hist-${event.sequence}-${snapshotLogs.length}`,
            time: formatHistoricalLogTime(event.timestamp),
          });
        };

        const upsertProgress = (title: string) => {
          const progressKey = `progress-${agentName || 'task'}-${eventType}`;
          const existingIndex = progressIndex.get(progressKey);
          const created = createLogItem({
            type: 'progress',
            title,
            progressKey,
            agentName,
          });
          const progressLog: LogItem = {
            ...created,
            id: `hist-progress-${progressKey}`,
            time: formatHistoricalLogTime(event.timestamp),
          };
          if (existingIndex !== undefined) {
            snapshotLogs[existingIndex] = progressLog;
            return;
          }
          progressIndex.set(progressKey, snapshotLogs.length);
          snapshotLogs.push(progressLog);
        };

        switch (eventType) {
          case 'thinking':
          case 'llm_thought':
          case 'react_thought':
            pushLog({
              type: 'thinking',
              title: message.slice(0, 100) + (message.length > 100 ? '...' : '') || 'Thinking...',
              content: cleanThinkingContent(message || (metadata.thought as string) || ''),
              agentName,
            });
            break;
          case 'llm_decision':
          case 'llm_complete':
            pushLog({
              type: 'info',
              title: message.slice(0, 100) + (message.length > 100 ? '...' : '') || 'Decision',
              content: message,
              agentName,
            });
            break;
          case 'final_answer':
            pushLog({
              type: 'info',
              title: 'Final Answer',
              content: metadata.result ? truncateOutput(JSON.stringify(metadata.result, null, 2)) : message,
              agentName,
            });
            break;
          case 'tool_call':
            pushLog({
              type: 'tool',
              title: `Tool: ${event.tool_name || 'unknown'}`,
              content: event.tool_input ? `Input:\n${JSON.stringify(event.tool_input, null, 2)}` : '',
              tool: {
                name: event.tool_name || 'unknown',
                status: 'running',
              },
              agentName,
            });
            break;
          case 'tool_result':
            pushLog({
              type: 'tool',
              title: `Completed: ${event.tool_name || 'unknown'}`,
              content: event.tool_output
                ? `Output:\n${truncateOutput(typeof event.tool_output === 'string' ? event.tool_output : JSON.stringify(event.tool_output, null, 2))}`
                : '',
              tool: {
                name: event.tool_name || 'unknown',
                duration: event.tool_duration_ms || 0,
                status: 'completed',
              },
              agentName,
            });
            break;
          case 'finding':
          case 'finding_new':
          case 'finding_verified':
            pushLog({
              type: 'finding',
              title: message || (metadata.title as string) || 'Vulnerability found',
              severity: (metadata.severity as string) || 'medium',
              agentName,
            });
            break;
          case 'dispatch':
          case 'dispatch_complete':
          case 'phase_start':
          case 'phase_complete':
          case 'node_start':
          case 'node_complete':
            pushLog({
              type: 'dispatch',
              title: message || `Event: ${eventType}`,
              content: message || undefined,
              agentName,
            });
            break;
          case 'progress':
            upsertProgress(message || 'Progress update');
            break;
          case 'info':
          case 'complete':
          case 'warning':
          case 'error':
            pushLog({
              type: eventType === 'error' ? 'error' : 'info',
              title: message || eventType,
              content: message || undefined,
              agentName,
            });
            break;
          case 'thinking_start':
          case 'thinking_end':
          case 'thinking_token':
          case 'llm_action':
          case 'llm_observation':
          case 'react_action':
          case 'react_observation':
          case 'model_response_raw':
            break;
          default:
            if (message) {
              pushLog({
                type: 'info',
                title: message,
                content: message,
                agentName,
              });
            }
        }
      }

      const mergedLogs = [...snapshotLogs, ...runtimeLogs].sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
      dispatch({ type: 'SET_LOGS', payload: mergedLogs });
      hasLoadedHistoricalEventsRef.current = true;
      setHistoricalEventsLoaded(true);
      setAfterSequence(lastEventSequenceRef.current);
      console.log(`[AgentAudit] Snapshot loaded ${mergedLogs.length} logs from ${events.length} events and ${runtimeLogs.length} runtime logs`);
      return mergedLogs.length;
    } catch (error) {
      console.error('[AgentAudit] Snapshot reload failed:', error);
      hasLoadedHistoricalEventsRef.current = false;
      setHistoricalEventsLoaded(false);
      return 0;
    }
  }, [taskId, dispatch, setAfterSequence, loadRuntimeSessionSnapshot]);

  // ============ Stream Event Handling ============

  const streamOptions = useMemo(() => ({
    includeThinking: true,
    includeToolCalls: true,
    // 馃敟 浣跨敤 state 鍙橀噺锛岀‘淇濆湪鍘嗗彶浜嬩欢鍔犺浇鍚庤兘鑾峰彇鏈€鏂板€?
    afterSequence: afterSequence,
    onEvent: (event: { type: string; message?: string; metadata?: { agent_name?: string; agent?: string } }) => {
      if (event.metadata?.agent_name) {
        setCurrentAgentName(event.metadata.agent_name);
      }

      const dispatchEvents = ['dispatch', 'dispatch_complete', 'node_start', 'phase_start', 'phase_complete'];
      if (dispatchEvents.includes(event.type)) {
        // 鎵€鏈?dispatch 绫诲瀷浜嬩欢閮芥坊鍔犲埌鏃ュ織
        dispatch({
          type: 'ADD_LOG',
          payload: {
            type: 'dispatch',
            title: event.message || `Agent dispatch: ${event.metadata?.agent || 'unknown'}`,
            agentName: getCurrentAgentName() || undefined,
          }
        });
        debouncedLoadAgentTree();
        return;
      }

      if (event.type === 'final_answer') {
        const metadata = event.metadata as { result?: unknown } | undefined;
        dispatch({
          type: 'ADD_LOG',
          payload: {
            type: 'info',
            title: 'Final Answer',
            content: metadata?.result ? truncateOutput(JSON.stringify(metadata.result, null, 2)) : (event.message || ''),
            agentName: getCurrentAgentName() || undefined,
          }
        });
        return;
      }

      // 馃敟 澶勭悊 info銆亀arning銆乪rror 绫诲瀷浜嬩欢锛堝厠闅嗚繘搴︺€佺储寮曡繘搴︾瓑锛?
      const infoEvents = ['info', 'warning', 'error', 'progress'];
      if (infoEvents.includes(event.type)) {
        const message = event.message || event.type;

        // 馃敟 妫€娴嬭繘搴︾被鍨嬫秷鎭紝浣跨敤鏇存柊鑰屼笉鏄坊鍔?
        const lowerMessage = message.toLowerCase();
        const looksLikeProgress =
          event.type === 'progress' ||
          lowerMessage.includes('progress') ||
          /(?:\d+\s*\/\s*\d+|\d+\s*%)/.test(message);

        if (looksLikeProgress) {
          dispatch({
            type: 'UPDATE_OR_ADD_PROGRESS_LOG',
            payload: {
              progressKey: `${getCurrentAgentName() || 'task'}_${event.type}`,
              title: message,
              agentName: getCurrentAgentName() || undefined,
            }
          });
        } else {
          dispatch({
            type: 'ADD_LOG',
            payload: {
              type: event.type === 'error' ? 'error' : 'info',
              title: message,
              content: message,
              agentName: getCurrentAgentName() || undefined,
            }
          });
        }
        return;
      }
    },
    onThinkingStart: () => {
      const currentId = getCurrentThinkingId();
      if (currentId) {
        updateLog(currentId, { isStreaming: false });
      }
      setCurrentThinkingId(null);
    },
    onThinkingToken: (_token: string, accumulated: string) => {
      if (!accumulated?.trim()) return;
      const cleanContent = cleanThinkingContent(accumulated);
      if (!cleanContent) return;

      const currentId = getCurrentThinkingId();
      if (!currentId) {
        // 棰勭敓鎴?ID锛岃繖鏍锋垜浠彲浠ヨ窡韪繖涓棩蹇?
        const newLogId = `thinking-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        dispatch({
          type: 'ADD_LOG', payload: {
            id: newLogId,
            type: 'thinking',
            title: 'Thinking...',
            content: cleanContent,
            isStreaming: true,
            agentName: getCurrentAgentName() || undefined,
          }
        });
        setCurrentThinkingId(newLogId);
      } else {
        updateLog(currentId, { content: cleanContent });
      }
    },
    onThinkingEnd: (response: string) => {
      const cleanResponse = cleanThinkingContent(response || "");
      const currentId = getCurrentThinkingId();

      if (!cleanResponse) {
        if (currentId) {
          removeLog(currentId);
        }
        setCurrentThinkingId(null);
        return;
      }

      if (currentId) {
        updateLog(currentId, {
          title: cleanResponse.slice(0, 100) + (cleanResponse.length > 100 ? '...' : ''),
          content: cleanResponse,
          isStreaming: false
        });
        setCurrentThinkingId(null);
      }
    },
    onToolStart: (name: string, input: Record<string, unknown>) => {
      const currentId = getCurrentThinkingId();
      if (currentId) {
        updateLog(currentId, { isStreaming: false });
        setCurrentThinkingId(null);
      }
      dispatch({
        type: 'ADD_LOG',
        payload: {
          type: 'tool',
          title: `Tool: ${name}`,
          content: `Input:\n${JSON.stringify(input, null, 2)}`,
          tool: { name, status: 'running' },
          agentName: getCurrentAgentName() || undefined,
        }
      });
    },
    onToolEnd: (name: string, output: unknown, duration: number) => {
      const outputStr = typeof output === 'string' ? output : JSON.stringify(output, null, 2);
      dispatch({
        type: 'COMPLETE_TOOL_LOG',
        payload: {
          toolName: name,
          output: truncateOutput(outputStr),
          duration,
        }
      });
    },
    onFinding: (finding: Record<string, unknown>) => {
      dispatch({
        type: 'ADD_LOG',
        payload: {
          type: 'finding',
          title: (finding.title as string) || 'Vulnerability found',
          severity: (finding.severity as string) || 'medium',
          agentName: getCurrentAgentName() || undefined,
        }
      });
      // 馃敟 鐩存帴灏?finding 娣诲姞鍒扮姸鎬侊紝涓嶄緷璧?API锛堝洜涓鸿繍琛屾椂鏁版嵁搴撹繕娌℃湁鏁版嵁锛?
      dispatch({
        type: 'ADD_FINDING',
        payload: {
          id: (finding.id as string) || `finding-${Date.now()}`,
          title: (finding.title as string) || 'Vulnerability found',
          severity: (finding.severity as string) || 'medium',
          vulnerability_type: (finding.vulnerability_type as string) || 'unknown',
          file_path: finding.file_path as string,
          line_start: finding.line_start as number,
          description: finding.description as string,
          is_verified: (finding.is_verified as boolean) || false,
        }
      });
    },
    onComplete: () => {
      dispatch({ type: 'ADD_LOG', payload: { type: 'info', title: 'Audit completed successfully' } });
      loadTask();
      loadFindings();
      loadAgentTree();
    },
    onError: (err: string) => {
      dispatch({ type: 'ADD_LOG', payload: { type: 'error', title: `Error: ${err}` } });
    },
  }), [afterSequence, dispatch, loadTask, loadFindings, loadAgentTree, debouncedLoadAgentTree,
    updateLog, removeLog, getCurrentAgentName, getCurrentThinkingId,
    setCurrentAgentName, setCurrentThinkingId]);

  const { connect: connectStream, disconnect: disconnectStream, isConnected } = useAgentStream(taskId || null, streamOptions);

  // 淇濆瓨 disconnect 鍑芥暟鍒?ref锛屼互渚垮湪 taskId 鍙樺寲鏃朵娇鐢?
  useEffect(() => {
    disconnectStreamRef.current = disconnectStream;
  }, [disconnectStream]);

  // ============ Effects ============

  // Status animation
  useEffect(() => {
    if (!isRunning) return;
    const dotTimer = setInterval(() => setStatusDots(d => (d + 1) % 4), 500);
    const verbTimer = setInterval(() => {
      setStatusVerb(ACTION_VERBS[Math.floor(Math.random() * ACTION_VERBS.length)]);
    }, 5000);
    return () => {
      clearInterval(dotTimer);
      clearInterval(verbTimer);
    };
  }, [isRunning]);

  // Initial load - 馃敟 鍔犺浇浠诲姟鏁版嵁鍜屽巻鍙蹭簨浠?
  useEffect(() => {
    if (!taskId) {
      setShowSplash(true);
      return;
    }
    setShowSplash(false);
    setLoading(true);
    setHistoricalEventsLoaded(false);

    const loadAllData = async () => {
      try {
        // 鍏堝姞杞戒换鍔″熀鏈俊鎭?
        await Promise.allSettled([loadTask(), loadFindings(), loadAgentTree()]);
        const loadedTask = await loadTask();
        const eventsLoaded = await loadHistoricalEventsSnapshot(loadedTask?.runtime_session_id ?? null);
        console.log(`[AgentAudit] Loaded ${eventsLoaded} historical events for task ${taskId}`);

        // 鏍囪鍘嗗彶浜嬩欢宸插姞杞藉畬鎴?(setAfterSequence 宸插湪 loadHistoricalEvents 涓皟鐢?
        setHistoricalEventsLoaded(true);
      } catch (error) {
        console.error('[AgentAudit] Failed to load data:', error);
        setHistoricalEventsLoaded(true); // 鍗充娇鍑洪敊涔熸爣璁颁负瀹屾垚锛岄伩鍏嶆棤闄愮瓑寰?
      } finally {
        setLoading(false);
      }
    };

    loadAllData();
  }, [taskId, loadTask, loadFindings, loadAgentTree, loadHistoricalEventsSnapshot, setLoading]);

  useEffect(() => {
    if (!taskId || isRunning || isLoading) return;
    if (logs.length > 0) return;
    if (hasLoadedHistoricalEventsRef.current && lastEventSequenceRef.current > 0) return;

    loadHistoricalEventsSnapshot(task?.runtime_session_id ?? null).then((eventsLoaded) => {
      if (eventsLoaded > 0) {
        setHistoricalEventsLoaded(true);
      }
    });
  }, [taskId, isRunning, isLoading, logs.length, task?.runtime_session_id, loadHistoricalEventsSnapshot]);

  // Stream connection - 馃敟 鍦ㄥ巻鍙蹭簨浠跺姞杞藉畬鎴愬悗杩炴帴
  useEffect(() => {
    // 绛夊緟鍘嗗彶浜嬩欢鍔犺浇瀹屾垚锛屼笖浠诲姟姝ｅ湪杩愯
    if (!taskId || !task?.status || task.status !== 'running') return;

    // 馃敟 浣跨敤 state 鍙橀噺纭繚鍦ㄥ巻鍙蹭簨浠跺姞杞藉畬鎴愬悗鎵嶈繛鎺?
    if (!historicalEventsLoaded) return;

    // 馃敟 閬垮厤閲嶅杩炴帴 - 鍙繛鎺ヤ竴娆?
    if (hasConnectedRef.current) return;

    hasConnectedRef.current = true;
    console.log(`[AgentAudit] Connecting to stream (afterSequence will be passed via streamOptions)`);
    connectStream();
    dispatch({ type: 'ADD_LOG', payload: { type: 'info', title: 'Connected to audit stream' } });

    return () => {
      console.log('[AgentAudit] Cleanup: disconnecting stream');
      disconnectStream();
    };
    // 馃敟 CRITICAL FIX: 绉婚櫎 afterSequence 渚濊禆锛?
    // afterSequence 閫氳繃 streamOptions 浼犻€掞紝涓嶉渶瑕佸湪杩欓噷瑙﹀彂閲嶈繛
    // 濡傛灉鍖呭惈瀹冿紝褰?loadHistoricalEvents 鏇存柊 afterSequence 鏃朵細瑙﹀彂鏂紑閲嶈繛
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskId, task?.status, historicalEventsLoaded, connectStream, disconnectStream, dispatch]);

  useEffect(() => {
    if (!taskId || task?.status !== 'running' || !task?.runtime_session_id) return;
    void mergeRuntimeSessionLogs(task.runtime_session_id);
    const interval = setInterval(() => {
      void mergeRuntimeSessionLogs(task.runtime_session_id);
    }, 5000);
    return () => clearInterval(interval);
  }, [taskId, task?.status, task?.runtime_session_id, mergeRuntimeSessionLogs]);

  // Polling
  useEffect(() => {
    if (!taskId || !isRunning) return;
    const interval = setInterval(loadAgentTree, POLLING_INTERVALS.AGENT_TREE);
    return () => clearInterval(interval);
  }, [taskId, isRunning, loadAgentTree]);

  useEffect(() => {
    if (!taskId || !isRunning) return;
    const interval = setInterval(loadTask, POLLING_INTERVALS.TASK_STATS);
    return () => clearInterval(interval);
  }, [taskId, isRunning, loadTask]);

  // ============ Handlers ============

  const handleAgentSelect = useCallback((agentId: string) => {
    if (selectedAgentId === agentId) {
      selectAgent(null);
    } else {
      selectAgent(agentId);
    }
  }, [selectedAgentId, selectAgent]);

  const handleCancel = async () => {
    if (!taskId || isCancelling) return;
    setIsCancelling(true);
    dispatch({ type: 'ADD_LOG', payload: { type: 'info', title: 'Requesting task cancellation...' } });

    try {
      await cancelAgentTask(taskId);
      toast.success("Task cancellation requested");
      dispatch({ type: 'ADD_LOG', payload: { type: 'info', title: 'Task cancellation confirmed' } });
      await loadTask();
      disconnectStream();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Failed to cancel task: ${errorMessage}`);
      dispatch({ type: 'ADD_LOG', payload: { type: 'error', title: `Failed to cancel: ${errorMessage}` } });
    } finally {
      setIsCancelling(false);
    }
  };

  const handleExportReport = () => {
    if (!task) return;
    setShowExportDialog(true);
  };

  // ============ Render ============

  if (showSplash && !taskId) {
    return (
      <>
        <SplashScreen onComplete={() => setShowCreateDialog(true)} />
        <CreateAgentTaskDialog open={showCreateDialog} onOpenChange={setShowCreateDialog} />
      </>
    );
  }

  if (isLoading && !task) {
    return (
      <div className="h-screen gradient-bg relative flex items-center justify-center overflow-hidden rounded-[34px] border border-white/65 bg-white/45 shadow-[0_24px_70px_rgba(88,97,110,0.10)] backdrop-blur-xl">
        {/* Grid background */}
        <div className="absolute inset-0 cyber-grid opacity-40" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(255,255,255,0.7),transparent_32%),radial-gradient(circle_at_bottom_right,rgba(214,230,236,0.35),transparent_26%)]" />
        {/* Vignette */}
        <div className="absolute inset-0 vignette pointer-events-none" />
        <div className="flex items-center gap-3 text-muted-foreground relative z-10">
          <Loader2 className="w-5 h-5 animate-spin text-primary" />
          <span className="text-sm text-slate-500">正在准备审计任务工作区...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex h-screen flex-col overflow-hidden rounded-[34px] border border-white/65 bg-white/45 shadow-[0_24px_70px_rgba(88,97,110,0.10)] backdrop-blur-xl">
      <div className="absolute inset-0 cyber-grid opacity-25 pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(255,255,255,0.72),transparent_30%),radial-gradient(circle_at_82%_12%,rgba(186,214,224,0.24),transparent_22%),radial-gradient(circle_at_bottom_right,rgba(232,205,177,0.18),transparent_28%)] pointer-events-none" />

      {/* Header */}
      <Header
        task={task}
        isRunning={isRunning}
        isCancelling={isCancelling}
        sessionHref={task?.runtime_session_id ? `/audit-sessions/${task.runtime_session_id}` : null}
        onCancel={handleCancel}
        onExport={handleExportReport}
        onNewAudit={() => setShowCreateDialog(true)}
      />

      {/* Main content */}
      <div className="relative z-10 flex flex-1 overflow-hidden px-4 pb-4">
        {/* Left Panel - Activity Log */}
        <div className="relative flex w-[68%] flex-col overflow-hidden rounded-[28px] border border-border/70 bg-white/82 shadow-[0_20px_48px_rgba(88,97,110,0.12)] backdrop-blur-xl">
          {/* Detail header */}
          <div className="flex-shrink-0 border-b border-border bg-card px-5 py-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-2.5">
                  {activeDetailView === 'activity' ? (
                    <Terminal className="w-4 h-4 text-primary" />
                  ) : (
                    <FileText className="w-4 h-4 text-primary" />
                  )}
                  <span className="uppercase font-bold tracking-wider text-foreground text-sm">
                    {activeDetailView === 'activity' ? 'Activity Log' : 'Final Report'}
                  </span>
                </div>
                {activeDetailView === 'activity' && isConnected && (
                  <div className="flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1">
                    <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">Live</span>
                  </div>
                )}
                <Badge variant="outline" className="h-6 px-2 text-xs border-border text-muted-foreground font-mono bg-muted">
                  {activeDetailView === 'activity'
                    ? `${filteredLogs.length}${!showAllLogs && logs.length !== filteredLogs.length ? ` / ${logs.length}` : ''} entries`
                    : `${findings.length} findings`}
                </Badge>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {isComplete && (
                  <div className="inline-flex rounded-full border border-border/70 bg-background/80 p-1 shadow-sm">
                    <button
                      type="button"
                      onClick={() => setActiveDetailView('activity')}
                      className={`rounded-full px-3 py-1.5 text-xs font-medium transition ${activeDetailView === 'activity' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                    >
                      Activity Log
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveDetailView('report')}
                      disabled={findings.length === 0}
                      className={`rounded-full px-3 py-1.5 text-xs font-medium transition ${activeDetailView === 'report' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'} disabled:cursor-not-allowed disabled:opacity-45`}
                    >
                      最终报告
                    </button>
                  </div>
                )}

              </div>
            </div>
          </div>

          {/* Detail content */}
          <div className="flex-1 overflow-hidden bg-[linear-gradient(180deg,rgba(255,255,255,0.56),rgba(245,238,229,0.72))]">
            {activeDetailView === 'activity' ? (
              <div className="h-full overflow-y-auto p-5 custom-scrollbar">
                {/* Filter indicator */}
                {selectedAgentId && !showAllLogs && (
                  <div className="mb-4 px-4 py-2.5 bg-primary/10 border border-primary/30 rounded-lg flex items-center justify-between">
                    <div className="flex items-center gap-2.5 text-sm text-primary">
                      <Filter className="w-3.5 h-3.5" />
                      <span className="font-medium">Filtering logs for selected agent</span>
                    </div>
                    <button
                      onClick={() => selectAgent(null)}
                      className="text-xs text-muted-foreground hover:text-primary font-mono uppercase px-2 py-1 rounded hover:bg-primary/10"
                    >
                      Clear Filter
                    </button>
                  </div>
                )}

                {/* Logs */}
                {filteredLogs.length === 0 ? (
                  <div className="h-full flex items-center justify-center">
                    <div className="text-center text-muted-foreground">
                      {isRunning ? (
                        <div className="flex flex-col items-center gap-3">
                          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                          <span className="text-sm font-mono tracking-wide">
                            {selectedAgentId && !showAllLogs
                              ? 'WAITING FOR ACTIVITY FROM SELECTED AGENT...'
                              : 'WAITING FOR AGENT ACTIVITY...'}
                          </span>
                        </div>
                      ) : (
                        <span className="text-sm font-mono tracking-wide">
                          {selectedAgentId && !showAllLogs
                            ? 'NO ACTIVITY FROM SELECTED AGENT'
                            : 'NO ACTIVITY YET'}
                        </span>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {filteredLogs.map(item => (
                      <LogEntry
                        key={item.id}
                        item={item}
                        isExpanded={expandedLogIds.has(item.id)}
                        onToggle={() => toggleLogExpanded(item.id)}
                      />
                    ))}
                  </div>
                )}
              </div>
            ) : findings.length > 0 || (task?.recovered_candidates_count ?? 0) > 0 ? (
              <div className="h-full overflow-y-auto p-5 custom-scrollbar">
                <FinalReportPanel task={task} findings={findings} recoveredCandidates={task?.recovered_candidates || []} />
              </div>
            ) : (
              <div className="flex h-full items-center justify-center p-6 text-center text-muted-foreground">
                <div>
                  <FileText className="mx-auto mb-3 h-8 w-8 text-muted-foreground/60" />
                  <p className="text-sm font-medium">当前任务还没有可展示的最终漏洞报告</p>
                  <p className="mt-2 text-xs">完成 verification 并产出 findings 后，这里会展示最终报告。</p>
                </div>
              </div>
            )}
          </div>

          {/* Status bar */}
          {task && (
            <div className="flex-shrink-0 h-10 border-t border-border flex items-center justify-between px-5 text-xs bg-card relative overflow-hidden">
              {/* Progress bar background */}
              <div
                className="absolute inset-0 bg-primary/10"
                style={{ width: `${task.progress_percentage || 0}%` }}
              />

              <span className="relative z-10">
                {isRunning ? (
                  <span className="flex items-center gap-2.5 text-emerald-600 dark:text-emerald-400">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                    <span className="font-mono font-semibold">{statusVerb}{'.'.repeat(statusDots)}</span>
                  </span>
                ) : isComplete ? (
                  <span className="flex items-center gap-2 text-muted-foreground font-mono">
                    <span className={`w-2 h-2 rounded-full ${task.status === 'completed' ? 'bg-emerald-500' : task.status === 'failed' ? 'bg-rose-500' : 'bg-amber-500'}`} />
                    AUDIT {task.status?.toUpperCase()}
                    {task.finding_outcome && task.finding_outcome !== 'none' ? (
                      <Badge
                        variant="outline"
                        className={`ml-2 font-mono text-[10px] ${
                          task.finding_outcome === 'finalized'
                            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600'
                            : task.finding_outcome === 'recovered_only'
                              ? 'border-sky-500/30 bg-sky-500/10 text-sky-600'
                              : 'border-amber-500/30 bg-amber-500/10 text-amber-700'
                        }`}
                      >
                        {task.finding_outcome === 'finalized'
                          ? 'FINALIZED'
                          : task.finding_outcome === 'recovered_only'
                            ? 'RECOVERED ONLY'
                            : 'INCOMPLETE'}
                      </Badge>
                    ) : null}
                  </span>
                ) : (
                  <span className="text-muted-foreground font-mono">READY</span>
                )}
              </span>
              <div className="flex items-center gap-5 font-mono text-muted-foreground relative z-10">
                <div className="flex items-center gap-1.5">
                  <span className="text-primary font-bold text-sm">{task.progress_percentage?.toFixed(0) || 0}</span>
                  <span className="text-muted-foreground text-xs">%</span>
                </div>
                <div className="w-px h-4 bg-border" />
                <div className="flex items-center gap-1.5">
                  <span className="text-foreground font-semibold">{task.analyzed_files}</span>
                  <span className="text-muted-foreground">/ {task.total_files}</span>
                  <span className="text-muted-foreground text-xs">files</span>
                </div>
                <div className="w-px h-4 bg-border" />
                <div className="flex items-center gap-1.5">
                  <span className="text-foreground font-semibold">{task.tool_calls_count || 0}</span>
                  <span className="text-muted-foreground text-xs">tools</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Panel - Agent Tree + Stats */}
        <div className="relative ml-4 flex w-[32%] flex-col overflow-hidden rounded-[28px] border border-border/70 bg-white/78 shadow-[0_20px_48px_rgba(88,97,110,0.10)] backdrop-blur-xl">
          {/* Agent Tree section */}
          <div className="flex-1 flex flex-col border-b border-border overflow-hidden">
            {/* Tree header */}
            <div className="flex-shrink-0 h-12 border-b border-border flex items-center justify-between px-4 bg-card">
              <div className="flex items-center gap-2.5 text-xs text-muted-foreground">
                <Bot className="w-4 h-4 text-violet-600 dark:text-violet-500" />
                <span className="uppercase font-bold tracking-wider text-foreground text-sm">
                  {selectedAgentId && !showAllLogs ? 'Agent Detail' : 'Agent Tree'}
                </span>
                {!selectedAgentId && agentTree && (
                  <Badge variant="outline" className="h-5 px-2 text-xs border-violet-500/30 text-violet-600 dark:text-violet-500 font-mono bg-violet-500/10">
                    {agentTree.total_agents}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2">
                {selectedAgentId && !showAllLogs && (
                  <button
                    onClick={() => selectAgent(null)}
                    className="text-xs text-primary hover:text-primary/80 font-mono uppercase px-2 py-1 rounded hover:bg-primary/10"
                  >
                    Back
                  </button>
                )}
                {!selectedAgentId && agentTree && agentTree.running_agents > 0 && (
                  <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                    <span className="text-xs font-mono text-emerald-600 dark:text-emerald-400 font-semibold">{agentTree.running_agents}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Tree content or Agent Detail */}
            <div className="flex-1 overflow-y-auto p-3 custom-scrollbar bg-[linear-gradient(180deg,rgba(255,255,255,0.58),rgba(244,237,228,0.68))]">
              {selectedAgentId && !showAllLogs ? (
                /* Agent Detail Panel - 瑕嗙洊鏁翠釜鍐呭鍖哄煙 */
                <AgentDetailPanel
                  agentId={selectedAgentId}
                  treeNodes={treeNodes}
                  onClose={() => selectAgent(null)}
                />
              ) : treeNodes.length > 0 ? (
                <div className="space-y-0.5">
                  {treeNodes.map(node => (
                    <AgentTreeNodeItem
                      key={node.agent_id}
                      node={node}
                      selectedId={selectedAgentId}
                      onSelect={handleAgentSelect}
                    />
                  ))}
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground text-xs">
                  {isRunning ? (
                    <div className="flex flex-col items-center gap-3 p-6">
                      <Loader2 className="w-6 h-6 animate-spin text-violet-600 dark:text-violet-500" />
                      <span className="font-mono text-center">INITIALIZING<br/>AGENTS...</span>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-2 p-6 text-center">
                      <Bot className="w-8 h-8 text-muted-foreground/50" />
                      <span className="font-mono">NO AGENTS YET</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Bottom section - Stats */}
          <div className="flex-shrink-0 p-4 bg-card">
            <StatsPanel task={task} findings={findings} />
          </div>
        </div>
      </div>

      {/* Create dialog */}
      <CreateAgentTaskDialog open={showCreateDialog} onOpenChange={setShowCreateDialog} />

      {/* Export dialog */}
      <ReportExportDialog
        open={showExportDialog}
        onOpenChange={setShowExportDialog}
        task={task}
        findings={findings}
      />
    </div>
  );
}

// Wrapped export with Error Boundary
export default function AgentAuditPage() {
  const navigate = useNavigate();
  const { taskId } = useParams<{ taskId: string }>();

  return (
    <AgentErrorBoundary
      taskId={taskId}
      onRetry={() => window.location.reload()}
    >
      <AgentAuditPageContent />
    </AgentErrorBoundary>
  );
}







