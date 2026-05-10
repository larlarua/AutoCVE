import { useEffect, useMemo, useState } from 'react';
import {
  Bot,
  BrainCircuit,
  Check,
  CheckCircle2,
  ChevronDown,
  KeyRound,
  Loader2,
  MessageSquareMore,
  Plus,
  RefreshCw,
  Save,
  ServerCog,
  Sparkles,
  Trash2,
  Wand2,
} from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import {
  type AgentChatMessage,
  type AgentModelConfig,
  type AgentModelTestResponse,
  type AgentType,
  type ModelProfileConfig,
  type ProviderOption,
  getModelConfig,
  getModelProviders,
  resetModelConfig,
  saveModelConfig,
  syncLocalLibraries,
  testAgentModel,
  testGlobalModel,
} from '@/shared/api/modelConfig';
import { cn } from '@/shared/utils/utils';

const AGENT_ORDER: AgentType[] = ['orchestrator', 'recon', 'scan', 'triage', 'finding', 'verification'];
const DEFAULT_TEST_PROMPT =
  'Please tell me which skill metadata you currently know, what your current role is, and give one concrete example of how you would use those skills.';

const AGENT_META: Record<AgentType, { label: string; description: string }> = {
  orchestrator: { label: 'Orchestrator', description: '负责固定流程编排与阶段分发。' },
  recon: { label: 'Recon', description: '负责轻量侦察、入口发现与上下文预热。' },
  scan: { label: 'Scan', description: '负责工具驱动扫描与候选问题发现。' },
  triage: { label: 'Triage', description: '负责误报过滤、证据补强与风险收束。' },
  finding: { label: 'Finding', description: '负责直接源码审阅与逻辑漏洞深挖。' },
  verification: { label: 'Verification', description: '负责高置信度问题验证与闭环确认。' },
};

const PRINCIPLE_CARDS = [
  {
    title: '一处设置，统一继承',
    description: '默认情况下，各 Agent 继承全局 provider、model、API Key 与 Base URL，只在确有需要时单独覆盖。',
  },
  {
    title: '搜索选择 + 手动输入',
    description: '模型选择支持搜索推荐项，也允许手动输入自定义模型 ID，适配官方接口与代理站两种场景。',
  },
  {
    title: '运行态可验证',
    description: '测试对话会回显实际生效的 provider/model 与技能元数据，方便快速确认真实运行配置。',
  },
];

const DEFAULT_AGENT_CONFIG: AgentModelConfig = {
  enabled: false,
  llmProvider: '',
  llmApiKey: '',
  llmModel: '',
  llmBaseUrl: '',
  llmTimeout: null,
  llmTemperature: null,
  llmMaxTokens: null,
  maxIterations: null,
  env: {},
  alwaysThinkingEnabled: false,
};

type GlobalModelConfig = Omit<ModelProfileConfig, 'id' | 'name'>;

const DEFAULT_GLOBAL_ENV = '{}';
const PANEL_CLASS =
  'rounded-[30px] border border-[rgba(176,196,187,.78)] bg-[linear-gradient(180deg,rgba(255,255,255,.98),rgba(244,249,246,.96))] shadow-[0_20px_50px_rgba(110,131,121,.10)] backdrop-blur';
const SOFT_PANEL_CLASS =
  'rounded-[24px] border border-[rgba(194,211,203,.84)] bg-[rgba(248,251,249,.94)] shadow-[0_14px_32px_rgba(116,135,126,.07)]';
const INPUT_CLASS =
  'h-11 rounded-[18px] border-[rgba(183,202,193,.95)] bg-white/90 font-sans text-[15px] text-[#23312b] shadow-none placeholder:text-[#7d8f87] focus:border-[#6d9581]';
const TEXTAREA_CLASS =
  'min-h-[140px] rounded-[22px] border-[rgba(183,202,193,.95)] bg-white/92 font-mono text-[13px] leading-6 text-[#23312b] shadow-none placeholder:text-[#80928b] focus:border-[#6d9581]';

function stringifyEnvPayload(value?: Record<string, string>): string {
  const payload = value && Object.keys(value).length > 0 ? value : {};
  return JSON.stringify(payload, null, 2);
}

function parseEnvPayload(raw: string, label: string): Record<string, string> {
  const trimmed = raw.trim();
  if (!trimmed) return {};

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }

  return Object.fromEntries(
    Object.entries(parsed as Record<string, unknown>)
      .filter(([, value]) => value !== null && value !== '')
      .map(([key, value]) => [key, String(value)])
  );
}

function cloneAgentConfig(input?: Partial<AgentModelConfig>): AgentModelConfig {
  return {
    ...DEFAULT_AGENT_CONFIG,
    ...(input || {}),
    env: input?.env || {},
    alwaysThinkingEnabled: false,
  };
}

function uniqueModels(models?: string[]): string[] {
  return Array.from(new Set((models || []).filter(Boolean)));
}

function createProfileId(): string {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  return `profile-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function cloneModelProfile(input?: Partial<ModelProfileConfig>): ModelProfileConfig {
  return {
    id: input?.id || createProfileId(),
    name: input?.name?.trim() || '未命名方案',
    llmProvider: input?.llmProvider || '',
    llmApiKey: input?.llmApiKey || '',
    llmModel: input?.llmModel || '',
    llmBaseUrl: input?.llmBaseUrl || '',
    llmTimeout: input?.llmTimeout ?? null,
    llmTemperature: input?.llmTemperature ?? null,
    llmMaxTokens: input?.llmMaxTokens ?? null,
    env: input?.env || {},
  };
}

function buildProfileFromGlobal(id: string, name: string, config: GlobalModelConfig, env: Record<string, string>): ModelProfileConfig {
  return cloneModelProfile({
    id,
    name,
    llmProvider: config.llmProvider,
    llmApiKey: config.llmApiKey,
    llmModel: config.llmModel,
    llmBaseUrl: config.llmBaseUrl,
    llmTimeout: config.llmTimeout,
    llmTemperature: config.llmTemperature,
    llmMaxTokens: config.llmMaxTokens,
    env,
  });
}

interface ModelSearchSelectProps {
  value: string;
  models: string[];
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
}

function ModelSearchSelect({
  value,
  models,
  onChange,
  disabled = false,
  placeholder = '搜索推荐模型',
}: ModelSearchSelectProps) {
  const [open, setOpen] = useState(false);
  const options = useMemo(() => uniqueModels(models), [models]);
  const selectedRecommended = options.includes(value) ? value : '';

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          disabled={disabled}
          className={cn(
            'h-11 w-full justify-between rounded-[18px] border-[rgba(183,202,193,.95)] bg-white/92 px-4 font-sans text-[15px] font-medium text-[#23312b] shadow-none hover:bg-[#f3f8f5]',
            !selectedRecommended && 'text-[#7d8f87]',
          )}
        >
          <span className="truncate">{selectedRecommended || placeholder}</span>
          <ChevronDown className="h-4 w-4 opacity-60" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-[--radix-popover-trigger-width] rounded-[22px] border-[rgba(183,202,193,.95)] bg-[rgba(252,254,253,.98)] p-0 font-sans shadow-[0_16px_36px_rgba(109,129,120,.14)]"
      >
        <Command className="rounded-[22px] bg-transparent">
          <CommandInput className="h-11 text-sm" placeholder="搜索当前 Provider 的推荐模型..." />
          <CommandList className="max-h-64">
            <CommandEmpty className="text-[#73857d]">没有匹配的推荐模型</CommandEmpty>
            <CommandGroup heading="推荐模型">
              {options.map((model) => (
                <CommandItem
                  key={model}
                  value={model}
                  className="rounded-[14px] px-3 py-2.5 text-[14px]"
                  onSelect={() => {
                    onChange(model);
                    setOpen(false);
                  }}
                >
                  <Check className={cn('h-4 w-4 text-[#5f8973]', value === model ? 'opacity-100' : 'opacity-0')} />
                  <span className="truncate">{model}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

export function SystemConfig() {
  const [providers, setProviders] = useState<ProviderOption[]>([]);
  const [globalConfig, setGlobalConfig] = useState({
    llmProvider: 'openai',
    llmApiKey: '',
    llmModel: '',
    llmBaseUrl: '',
    llmTimeout: 150000,
    llmTemperature: 0.1,
    llmMaxTokens: 4096,
    env: {} as Record<string, string>,
  });
  const [agentConfigs, setAgentConfigs] = useState<Record<AgentType, AgentModelConfig>>({
    orchestrator: cloneAgentConfig(),
    recon: cloneAgentConfig(),
    scan: cloneAgentConfig(),
    triage: cloneAgentConfig(),
    finding: cloneAgentConfig(),
    verification: cloneAgentConfig(),
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingGlobal, setTestingGlobal] = useState(false);
  const [syncingAssets, setSyncingAssets] = useState(false);
  const [globalEnvText, setGlobalEnvText] = useState(DEFAULT_GLOBAL_ENV);
  const [modelProfiles, setModelProfiles] = useState<ModelProfileConfig[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [profileDialogOpen, setProfileDialogOpen] = useState(false);
  const [profileNameDraft, setProfileNameDraft] = useState('');
  const [agentEnvTexts, setAgentEnvTexts] = useState<Record<AgentType, string>>({
    orchestrator: DEFAULT_GLOBAL_ENV,
    recon: DEFAULT_GLOBAL_ENV,
    scan: DEFAULT_GLOBAL_ENV,
    triage: DEFAULT_GLOBAL_ENV,
    finding: DEFAULT_GLOBAL_ENV,
    verification: DEFAULT_GLOBAL_ENV,
  });

  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [activeTestAgent, setActiveTestAgent] = useState<AgentType>('scan');
  const [testPrompt, setTestPrompt] = useState(DEFAULT_TEST_PROMPT);
  const [testResult, setTestResult] = useState<AgentModelTestResponse | null>(null);
  const [testingAgent, setTestingAgent] = useState(false);
  const [chatMessages, setChatMessages] = useState<AgentChatMessage[]>([]);
  const [chatInput, setChatInput] = useState(DEFAULT_TEST_PROMPT);
  const [composerMode, setComposerMode] = useState<'initial' | 'followup'>('initial');

  const providerMap = useMemo(
    () => Object.fromEntries(providers.map((item) => [item.value, item])) as Record<string, ProviderOption>,
    [providers],
  );
  const selectedProfile = useMemo(
    () => modelProfiles.find((profile) => profile.id === selectedProfileId) || null,
    [modelProfiles, selectedProfileId],
  );

  const loadPage = async () => {
    try {
      setLoading(true);
      const [providerResponse, configResponse] = await Promise.all([getModelProviders(), getModelConfig()]);
      setProviders(providerResponse.providers);
      const llmConfig = configResponse.llmConfig || {};
      setGlobalConfig({
        llmProvider: llmConfig.llmProvider || 'openai',
        llmApiKey: llmConfig.llmApiKey || '',
        llmModel: llmConfig.llmModel || '',
        llmBaseUrl: llmConfig.llmBaseUrl || '',
        llmTimeout: llmConfig.llmTimeout || 150000,
        llmTemperature: llmConfig.llmTemperature ?? 0.1,
        llmMaxTokens: llmConfig.llmMaxTokens || 4096,
        env: llmConfig.env || {},
      });
      setGlobalEnvText(stringifyEnvPayload(llmConfig.env));
      const profiles = Array.isArray(llmConfig.modelProfiles)
        ? llmConfig.modelProfiles.map((profile: Partial<ModelProfileConfig>) => cloneModelProfile(profile))
        : [];
      setModelProfiles(profiles);
      setSelectedProfileId((prev) => (profiles.some((profile) => profile.id === prev) ? prev : profiles[0]?.id || ''));

      const nextAgentConfigs = {} as Record<AgentType, AgentModelConfig>;
      const nextAgentEnvTexts = {} as Record<AgentType, string>;
      for (const agent of AGENT_ORDER) {
        nextAgentConfigs[agent] = cloneAgentConfig(llmConfig.agentConfigs?.[agent]);
        nextAgentEnvTexts[agent] = stringifyEnvPayload(llmConfig.agentConfigs?.[agent]?.env);
      }
      setAgentConfigs(nextAgentConfigs);
      setAgentEnvTexts(nextAgentEnvTexts);
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'Failed to load model config');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadPage();
  }, []);

  const updateAgentConfig = (agent: AgentType, patch: Partial<AgentModelConfig>) => {
    setAgentConfigs((prev) => ({ ...prev, [agent]: { ...prev[agent], ...patch } }));
  };

  const updateAgentEnvText = (agent: AgentType, value: string) => {
    setAgentEnvTexts((prev) => ({ ...prev, [agent]: value }));
  };

  const openSaveProfileDialog = () => {
    setProfileNameDraft('');
    setProfileDialogOpen(true);
  };

  const createProfileFromCurrentGlobal = () => {
    const name = profileNameDraft.trim();
    if (!name) {
      toast.error('请先输入方案名称');
      return;
    }

    try {
      const parsedGlobalEnv = parseEnvPayload(globalEnvText, 'Global env JSON');
      const nextProfile = buildProfileFromGlobal(createProfileId(), name, globalConfig, parsedGlobalEnv);
      setModelProfiles((prev) => [...prev, nextProfile]);
      setSelectedProfileId(nextProfile.id);
      setProfileDialogOpen(false);
      setProfileNameDraft('');
      toast.success('已添加模型方案，点击保存模型配置后持久化');
    } catch (error: any) {
      toast.error(error?.message || 'Failed to create model profile');
    }
  };

  const updateSelectedProfileFromCurrentGlobal = () => {
    if (!selectedProfile) {
      toast.error('请先选择一个模型方案');
      return;
    }

    try {
      const parsedGlobalEnv = parseEnvPayload(globalEnvText, 'Global env JSON');
      const nextProfile = buildProfileFromGlobal(selectedProfile.id, selectedProfile.name, globalConfig, parsedGlobalEnv);
      setModelProfiles((prev) => prev.map((profile) => (profile.id === selectedProfile.id ? nextProfile : profile)));
      toast.success('已更新当前方案，点击保存模型配置后持久化');
    } catch (error: any) {
      toast.error(error?.message || 'Failed to update model profile');
    }
  };

  const applySelectedProfile = () => {
    if (!selectedProfile) {
      toast.error('请先选择一个模型方案');
      return;
    }

    setGlobalConfig((prev) => ({
      ...prev,
      llmProvider: selectedProfile.llmProvider || 'openai',
      llmApiKey: selectedProfile.llmApiKey || '',
      llmModel: selectedProfile.llmModel || '',
      llmBaseUrl: selectedProfile.llmBaseUrl || '',
      llmTimeout: selectedProfile.llmTimeout ?? prev.llmTimeout,
      llmTemperature: selectedProfile.llmTemperature ?? prev.llmTemperature,
      llmMaxTokens: selectedProfile.llmMaxTokens ?? prev.llmMaxTokens,
      env: selectedProfile.env || {},
    }));
    setGlobalEnvText(stringifyEnvPayload(selectedProfile.env));
    toast.success(`已应用模型方案：${selectedProfile.name}`);
  };

  const deleteSelectedProfile = () => {
    if (!selectedProfile) {
      toast.error('请先选择一个模型方案');
      return;
    }

    setModelProfiles((prev) => {
      const next = prev.filter((profile) => profile.id !== selectedProfile.id);
      setSelectedProfileId(next[0]?.id || '');
      return next;
    });
    toast.success('已删除当前方案，点击保存模型配置后持久化');
  };

  const saveAll = async () => {
    try {
      setSaving(true);
      const parsedGlobalEnv = parseEnvPayload(globalEnvText, 'Global env JSON');
      const nextAgentConfigs = AGENT_ORDER.reduce<Record<AgentType, AgentModelConfig>>((acc, agent) => {
        acc[agent] = {
          ...agentConfigs[agent],
          env: parseEnvPayload(agentEnvTexts[agent] || DEFAULT_GLOBAL_ENV, `${agent} env JSON`),
          alwaysThinkingEnabled: false,
        };
        return acc;
      }, {} as Record<AgentType, AgentModelConfig>);

      await saveModelConfig({
        llmConfig: {
          ...globalConfig,
          env: parsedGlobalEnv,
          alwaysThinkingEnabled: false,
          modelProfiles: modelProfiles.map((profile) => cloneModelProfile(profile)),
          agentConfigs: nextAgentConfigs,
        },
      });
      setGlobalConfig((prev) => ({ ...prev, env: parsedGlobalEnv }));
      setAgentConfigs(nextAgentConfigs);
      toast.success('Model configuration saved');
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'Failed to save model config');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    try {
      await resetModelConfig();
      toast.success('Default model configuration restored');
      await loadPage();
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'Failed to reset model config');
    }
  };

  const handleGlobalTest = async () => {
    try {
      setTestingGlobal(true);
      const result = await testGlobalModel({
        provider: globalConfig.llmProvider,
        apiKey: globalConfig.llmApiKey,
        model: globalConfig.llmModel,
        baseUrl: globalConfig.llmBaseUrl,
        prompt: 'Reply with exactly: connection-ok',
      });
      if (result.success) {
        toast.success(`${result.provider} / ${result.model} connection ok`);
      } else {
        toast.error(result.message || 'Global model test failed');
      }
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'Global model test failed');
    } finally {
      setTestingGlobal(false);
    }
  };

  const handleSyncAssets = async () => {
    try {
      setSyncingAssets(true);
      const result = await syncLocalLibraries();
      toast.success(`Synced ${result.skills_synced} skills and ${result.templates_synced} templates`);
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'Failed to sync local libraries');
    } finally {
      setSyncingAssets(false);
    }
  };

  const openAgentTest = (agent: AgentType) => {
    setActiveTestAgent(agent);
    setTestResult(null);
    setChatMessages([]);
    setTestPrompt(DEFAULT_TEST_PROMPT);
    setChatInput(DEFAULT_TEST_PROMPT);
    setComposerMode('initial');
    setTestDialogOpen(true);
  };

  const runAgentTest = async (promptOverride?: string) => {
    const sourcePrompt = composerMode === 'initial' ? testPrompt : chatInput;
    const nextPrompt = (promptOverride ?? sourcePrompt).trim();
    if (!nextPrompt) {
      toast.error('Please enter a message first');
      return;
    }

    const nextMessages: AgentChatMessage[] = [...chatMessages, { role: 'user', content: nextPrompt }];
    try {
      setTestingAgent(true);
      const result = await testAgentModel({
        agent_type: activeTestAgent,
        prompt: nextPrompt,
        include_skills: true,
        agent_model_config: agentConfigs[activeTestAgent],
        messages: nextMessages,
      });
      setTestResult(result);
      if (result.success) {
        setChatMessages([...nextMessages, { role: 'assistant', content: result.response || result.message || 'No response' }]);
        setChatInput('');
        setComposerMode('followup');
        toast.success(`${activeTestAgent} agent test completed`);
      } else {
        toast.error(result.message || 'Agent model test failed');
      }
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'Agent model test failed');
    } finally {
      setTestingAgent(false);
    }
  };

  if (loading) {
    return <div className="flex min-h-[360px] items-center justify-center text-[#6f837a]">Loading model configuration...</div>;
  }

  return (
    <div className="space-y-6">
      <section className="overflow-hidden rounded-[34px] border border-[rgba(176,196,187,.74)] bg-[linear-gradient(135deg,rgba(250,252,251,.98),rgba(238,246,242,.96))] p-8 shadow-[0_24px_64px_rgba(115,132,123,.12)]">
        <div className="flex flex-col gap-8 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-3xl space-y-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-[rgba(138,170,155,.42)] bg-white/80 px-4 py-1 text-xs uppercase tracking-[0.22em] text-[#68857a]">
              <ServerCog className="h-3.5 w-3.5" />
              Model Console
            </div>
            <div>
              <h1 className="text-4xl font-black tracking-tight text-[#2d241a]">模型管理</h1>
                <p className="mt-3 max-w-2xl text-sm leading-7 text-[#60756c]">
                  统一管理全局模型与各 Agent 独立模型配置。界面已收拢为更轻量的浅灰浅绿控制台风格，减少噪音，保留运行时验证能力。
                </p>
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <div className="rounded-[20px] border border-[rgba(184,203,194,.72)] bg-white/78 p-4">
                  <div className="text-xs uppercase tracking-[0.16em] text-[#7c9288]">Model Input</div>
                  <div className="mt-2 text-sm font-semibold text-[#25332d]">可搜索下拉 + 手动输入</div>
                </div>
                <div className="rounded-[20px] border border-[rgba(184,203,194,.72)] bg-white/78 p-4">
                  <div className="text-xs uppercase tracking-[0.16em] text-[#7c9288]">Runtime Env</div>
                  <div className="mt-2 text-sm font-semibold text-[#25332d]">手动配置 Env（JSON）</div>
                </div>
                <div className="rounded-[20px] border border-[rgba(184,203,194,.72)] bg-white/78 p-4">
                  <div className="text-xs uppercase tracking-[0.16em] text-[#7c9288]">Agent Override</div>
                  <div className="mt-2 text-sm font-semibold text-[#25332d]">按需单独覆盖运行模型</div>
                </div>
              </div>
            </div>
          <div className="flex flex-wrap gap-3">
            <Button variant="outline" className="h-11 rounded-full border-[rgba(176,196,187,.82)] bg-white/82" onClick={handleSyncAssets} disabled={syncingAssets}>
              {syncingAssets ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              同步本地目录
            </Button>
            <Button variant="outline" className="h-11 rounded-full border-[rgba(176,196,187,.82)] bg-white/82" onClick={handleReset}>
              恢复默认
            </Button>
            <Button className="h-11 rounded-full border border-[#6c9681] bg-[#6c9681] text-white hover:bg-[#5b846f]" onClick={saveAll} disabled={saving}>
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
              保存模型配置
            </Button>
          </div>
        </div>
      </section>

      <section className={cn(PANEL_CLASS, 'p-6 md:p-7')}>
        <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div className="max-w-2xl">
            <div className="text-xs uppercase tracking-[0.18em] text-[#789187]">Model Profiles</div>
            <h2 className="mt-2 text-2xl font-bold text-[#2f2418]">模型配置方案</h2>
            <p className="mt-2 text-sm leading-7 text-[#62766d]">
              保存常用的全局模型组合，例如智谱、DeepSeek、Claude 或代理站配置。应用方案只覆盖全局默认模型，不修改各 Agent 的独立模型。
            </p>
          </div>
          <div className="grid w-full gap-3 xl:w-[620px] xl:grid-cols-[minmax(0,1fr)_auto]">
            <Select value={selectedProfileId} onValueChange={setSelectedProfileId}>
              <SelectTrigger className={INPUT_CLASS}>
                <SelectValue placeholder={modelProfiles.length ? '选择模型方案' : '暂无模型方案'} />
              </SelectTrigger>
              <SelectContent>
                {modelProfiles.map((profile) => (
                  <SelectItem key={profile.id} value={profile.id}>
                    {profile.name} · {profile.llmProvider || 'provider'} / {profile.llmModel || 'model'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" className="rounded-full border-[rgba(176,196,187,.82)] bg-white/82" onClick={openSaveProfileDialog}>
                <Plus className="mr-2 h-4 w-4" /> 保存为方案
              </Button>
              <Button variant="outline" className="rounded-full border-[rgba(176,196,187,.82)] bg-white/82" onClick={updateSelectedProfileFromCurrentGlobal} disabled={!selectedProfile}>
                <Save className="mr-2 h-4 w-4" /> 更新方案
              </Button>
              <Button className="rounded-full border border-[#6c9681] bg-[#6c9681] text-white hover:bg-[#5b846f]" onClick={applySelectedProfile} disabled={!selectedProfile}>
                应用方案
              </Button>
              <Button variant="outline" className="rounded-full border-[rgba(209,170,158,.82)] bg-white/82 text-[#9a4d3d] hover:text-[#873b2e]" onClick={deleteSelectedProfile} disabled={!selectedProfile}>
                <Trash2 className="mr-2 h-4 w-4" /> 删除
              </Button>
            </div>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap gap-2 text-xs text-[#6d8178]">
          {modelProfiles.length ? (
            modelProfiles.map((profile) => (
              <button
                key={profile.id}
                type="button"
                onClick={() => setSelectedProfileId(profile.id)}
                className={cn(
                  'rounded-full border px-3 py-1.5 transition',
                  selectedProfileId === profile.id
                    ? 'border-[#6c9681] bg-[rgba(108,150,129,.14)] text-[#3f6555]'
                    : 'border-[rgba(184,203,194,.72)] bg-white/78 hover:bg-[#f3f8f5]',
                )}
              >
                {profile.name}
              </button>
            ))
          ) : (
            <span className="rounded-full border border-dashed border-[rgba(184,203,194,.9)] px-3 py-1.5">还没有保存的模型方案</span>
          )}
        </div>
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_360px]">
        <div className={cn(PANEL_CLASS, 'p-6 md:p-7')}>
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <h2 className="text-2xl font-bold text-[#2f2418]">全局默认模型</h2>
              <p className="mt-2 text-sm leading-7 text-[#62766d]">没有单独覆盖的 Agent 会继承这里的 provider、model、API Key 和 Base URL。</p>
            </div>
            <Button variant="outline" className="rounded-full border-[rgba(176,196,187,.82)] bg-white/82" onClick={handleGlobalTest} disabled={testingGlobal}>
              {testingGlobal ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Wand2 className="mr-2 h-4 w-4" />}
              连接测试
            </Button>
          </div>
          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            <div className={cn(SOFT_PANEL_CLASS, 'p-4')}>
              <Label className="text-sm font-semibold text-[#31423a]">Provider</Label>
              <Select
                value={globalConfig.llmProvider}
                onValueChange={(value) =>
                  setGlobalConfig((prev) => ({
                    ...prev,
                    llmProvider: value,
                    llmModel: providerMap[value]?.default_model || '',
                  }))
                }
              >
                <SelectTrigger className={cn(INPUT_CLASS, 'mt-3')}>
                  <SelectValue placeholder="选择 Provider" />
                </SelectTrigger>
                <SelectContent>
                  {providers.map((item) => (
                    <SelectItem key={item.value} value={item.value}>
                      {item.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className={cn(SOFT_PANEL_CLASS, 'p-4')}>
              <Label className="text-sm font-semibold text-[#31423a]">Model</Label>
              <div className="mt-3 grid gap-3 xl:grid-cols-[220px_minmax(0,1fr)]">
                <ModelSearchSelect
                  value={globalConfig.llmModel}
                  models={providerMap[globalConfig.llmProvider]?.models || []}
                  onChange={(value) => setGlobalConfig((prev) => ({ ...prev, llmModel: value }))}
                />
                <Input
                  className={INPUT_CLASS}
                  value={globalConfig.llmModel}
                  onChange={(event) => setGlobalConfig((prev) => ({ ...prev, llmModel: event.target.value }))}
                  placeholder="手动输入自定义模型 ID"
                />
              </div>
              <p className="mt-3 text-xs leading-6 text-[#6d8178]">先从推荐列表搜索，也可以直接手动输入代理站或自定义别名模型。</p>
            </div>
            <div className={cn(SOFT_PANEL_CLASS, 'p-4 xl:col-span-2')}>
              <Label className="text-sm font-semibold text-[#31423a]">API Key</Label>
              <Input
                className={cn(INPUT_CLASS, 'mt-3')}
                type="password"
                value={globalConfig.llmApiKey}
                onChange={(event) => setGlobalConfig((prev) => ({ ...prev, llmApiKey: event.target.value }))}
                placeholder="sk-... / zhipu-... / kimi-..."
              />
            </div>
            <div className={cn(SOFT_PANEL_CLASS, 'p-4 xl:col-span-2')}>
              <Label className="text-sm font-semibold text-[#31423a]">Base URL</Label>
              <Input
                className={cn(INPUT_CLASS, 'mt-3')}
                value={globalConfig.llmBaseUrl}
                onChange={(event) => setGlobalConfig((prev) => ({ ...prev, llmBaseUrl: event.target.value }))}
                placeholder="留空则使用默认地址"
              />
            </div>
            <div className={cn(SOFT_PANEL_CLASS, 'p-4 xl:col-span-2')}>
              <Label className="text-sm font-semibold text-[#31423a]">手动配置 Env（JSON）</Label>
              <Textarea
                rows={6}
                className={cn(TEXTAREA_CLASS, 'mt-3')}
                value={globalEnvText}
                onChange={(event) => setGlobalEnvText(event.target.value)}
                placeholder={'{\n  "ANTHROPIC_AUTH_TOKEN": "sk-...",\n  "ANTHROPIC_BASE_URL": "https://pureopus.cc",\n  "ANTHROPIC_MODEL": "claude-opus-4-6",\n  "API_TIMEOUT_MS": "3000000"\n}'}
              />
              <p className="mt-3 text-xs leading-6 text-[#6d8178]">用于手动覆盖运行时环境变量，可指定 API Key、Base URL、Model、Timeout 等值。</p>
            </div>
          </div>
        </div>

        <aside className={cn(PANEL_CLASS, 'p-6')}>
          <h2 className="text-2xl font-bold text-[#2f2418]">配置原则</h2>
          <div className="mt-5 space-y-4 text-sm leading-7 text-[#6b5846]">
            <div className="rounded-2xl border border-[rgba(223,210,188,.92)] bg-[#fffaf3] p-4">
              <div className="flex items-center gap-2 font-semibold text-[#3d2f22]"><BrainCircuit className="h-4 w-4 text-[#c96532]" /> One agent, one model</div>
              <p className="mt-2">You can assign GLM to scan, GPT to finding, and a different provider again to verification.</p>
            </div>
            <div className="rounded-2xl border border-[rgba(223,210,188,.92)] bg-[#fffaf3] p-4">
              <div className="flex items-center gap-2 font-semibold text-[#3d2f22]"><Sparkles className="h-4 w-4 text-[#c96532]" /> Skills-aware test chat</div>
              <p className="mt-2">The test endpoint returns the effective provider/model plus the loaded and matched skill metadata, so you can verify what the model actually saw.</p>
            </div>
            <div className="rounded-2xl border border-[rgba(223,210,188,.92)] bg-[#fffaf3] p-4">
              <div className="flex items-center gap-2 font-semibold text-[#3d2f22]"><KeyRound className="h-4 w-4 text-[#c96532]" /> Override only when needed</div>
              <p className="mt-2">If “独立模型” is off, the agent keeps using the global provider/model and API key.</p>
            </div>
          </div>
        </aside>
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        {AGENT_ORDER.map((agent) => {
          const config = agentConfigs[agent];
          const provider = providerMap[config.llmProvider || globalConfig.llmProvider];
          return (
            <article key={agent} className={cn(PANEL_CLASS, 'p-6')}>
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-[18px] bg-[rgba(108,150,129,.12)] text-[#678e79]"><Bot className="h-5 w-5" /></div>
                  <div>
                    <h3 className="text-2xl font-bold text-[#22302a]">{AGENT_META[agent].label}</h3>
                    <p className="mt-1 text-sm leading-7 text-[#647970]">{AGENT_META[agent].description}</p>
                  </div>
                </div>
                <div className="inline-flex items-center gap-3 rounded-full border border-[rgba(180,200,191,.88)] bg-[rgba(247,251,249,.92)] px-4 py-2">
                  <span className="text-sm font-medium text-[#6a5645]">独立模型</span>
                  <Switch checked={config.enabled} onCheckedChange={(checked) => updateAgentConfig(agent, { enabled: checked })} />
                </div>
              </div>
              {!config.enabled ? (
                <div className="mt-5 rounded-[20px] border border-dashed border-[rgba(187,205,196,.92)] bg-[rgba(247,250,248,.88)] px-4 py-3 text-sm text-[#688077]">
                  当前未启用独立模型，运行时会继承全局 provider / model / API Key / Base URL。
                </div>
              ) : null}
              <div className="mt-5 grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Provider</Label>
                  <Select
                    value={config.llmProvider || globalConfig.llmProvider}
                    onValueChange={(value) => updateAgentConfig(agent, { llmProvider: value, llmModel: providerMap[value]?.default_model || '' })}
                  >
                    <SelectTrigger className={INPUT_CLASS}><SelectValue /></SelectTrigger>
                    <SelectContent>{providers.map((item) => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>Model</Label>
                  <div className="grid gap-3 xl:grid-cols-[220px_minmax(0,1fr)]">
                    <ModelSearchSelect
                      value={config.llmModel || ''}
                      models={provider?.models || []}
                      onChange={(value) => updateAgentConfig(agent, { llmModel: value })}
                    />
                    <Input
                      className={INPUT_CLASS}
                      value={config.llmModel || ''}
                      onChange={(event) => updateAgentConfig(agent, { llmModel: event.target.value })}
                      placeholder="手动输入自定义模型 ID"
                    />
                  </div>
                  <p className="text-xs leading-6 text-[#6d8178]">支持搜索推荐模型，也支持直接手动输入。</p>
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>Agent API Key</Label>
                  <Input className={INPUT_CLASS} type="password" value={config.llmApiKey || ''} onChange={(event) => updateAgentConfig(agent, { llmApiKey: event.target.value })} placeholder="留空则继承全局 API Key" />
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>Agent Base URL</Label>
                  <Input className={INPUT_CLASS} value={config.llmBaseUrl || ''} onChange={(event) => updateAgentConfig(agent, { llmBaseUrl: event.target.value })} placeholder="留空则继承全局 Base URL" />
                </div>
                <div className="space-y-2">
                  <Label>Max Iterations</Label>
                  <Input
                    className={INPUT_CLASS}
                    type="number"
                    min={1}
                    value={config.maxIterations ?? ''}
                    onChange={(event) =>
                      updateAgentConfig(agent, {
                        maxIterations: event.target.value ? Number(event.target.value) : null,
                      })
                    }
                    placeholder="留空则使用当前默认值"
                  />
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>手动配置 Env（JSON）</Label>
                  <Textarea
                    rows={6}
                    className={TEXTAREA_CLASS}
                    value={agentEnvTexts[agent] || DEFAULT_GLOBAL_ENV}
                    onChange={(event) => updateAgentEnvText(agent, event.target.value)}
                    placeholder={'{\n  "ANTHROPIC_AUTH_TOKEN": "sk-...",\n  "ANTHROPIC_BASE_URL": "https://pureopus.cc",\n  "ANTHROPIC_MODEL": "claude-opus-4-6"\n}'}
                  />
                  <p className="text-xs leading-6 text-[#6d8178]">仅为当前 Agent 手动补充运行时 Env；留空时会继续沿用全局 Env 覆写。</p>
                </div>
              </div>
              <div className="mt-5 flex flex-wrap items-center gap-3 text-sm text-[#705d4b]">
                <div className="rounded-full bg-[rgba(108,150,129,.12)] px-3 py-1.5 text-[#4b6559]">
                  Effective model: {config.enabled ? (config.llmModel || provider?.default_model || 'not set') : globalConfig.llmModel || providerMap[globalConfig.llmProvider]?.default_model || 'not set'}
                </div>
                <Button variant="outline" className="rounded-full border-[rgba(176,196,187,.82)] bg-white/82" onClick={() => openAgentTest(agent)}>
                  <MessageSquareMore className="mr-2 h-4 w-4" /> 测试对话
                </Button>
              </div>
            </article>
          );
        })}
      </section>

      <Dialog open={profileDialogOpen} onOpenChange={setProfileDialogOpen}>
        <DialogContent className="border-[rgba(176,196,187,.78)] bg-[rgba(252,254,253,.98)] sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-2xl font-black text-[#2f2418]">保存模型方案</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Label className="text-sm font-semibold text-[#31423a]">方案名称</Label>
            <Input
              className={INPUT_CLASS}
              value={profileNameDraft}
              onChange={(event) => setProfileNameDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  createProfileFromCurrentGlobal();
                }
              }}
              placeholder="例如：智谱 GLM / DeepSeek / Claude"
              autoFocus
            />
            <p className="text-xs leading-6 text-[#6d8178]">会保存当前全局 provider、model、API Key、Base URL、参数和 Env JSON。</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setProfileDialogOpen(false)}>
              取消
            </Button>
            <Button className="bg-[#6c9681] text-white hover:bg-[#5b846f]" onClick={createProfileFromCurrentGlobal}>
              保存方案
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={testDialogOpen} onOpenChange={setTestDialogOpen}>
        <DialogContent className="flex w-[min(1120px,calc(100vw-1.5rem))] max-w-6xl flex-col overflow-hidden border-[rgba(215,194,161,.8)] bg-[linear-gradient(180deg,rgba(255,255,255,.98),rgba(249,243,233,.98))] p-0 sm:max-h-[88vh]">
          <DialogHeader className="border-b border-[rgba(223,210,188,.92)] bg-white/75 pb-5 pr-14">
            <DialogTitle className="text-2xl font-black text-[#2f2418]">{activeTestAgent} Agent 模型测试</DialogTitle>
          </DialogHeader>
          <div className="grid flex-1 gap-5 overflow-hidden px-6 py-5 lg:grid-cols-[.95fr_1.05fr]">
            <div className="flex min-h-0 flex-col overflow-hidden">
              <div className="rounded-[24px] border border-[rgba(223,210,188,.92)] bg-[#fffdfa] p-5 text-sm leading-7 text-[#6b5846]">
                This test uses the runtime config for the <span className="font-semibold text-[#2f2318]">{activeTestAgent} Agent</span> and injects the matched skill metadata into the same initial user-side context used by the real agent startup flow.
              </div>

              <div className="mt-4 flex min-h-0 flex-1 flex-col rounded-[24px] border border-[rgba(223,210,188,.92)] bg-[#fffdfa] p-5">
                <div className="mb-3 text-sm font-semibold text-[#2f2318]">对话窗口</div>
                <ScrollArea className="min-h-0 flex-1 rounded-2xl bg-[#fcf7f0] p-3">
                  {!chatMessages.length ? (
                    <div className="text-sm leading-7 text-[#7a6654]">
                      No messages yet. Start with the default prompt to confirm which skill metadata is loaded, then continue with follow-up questions about how the agent would use those skills.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {chatMessages.map((message, index) => (
                        <div
                          key={`${message.role}-${index}`}
                          className={`rounded-2xl px-4 py-3 text-sm leading-7 ${
                            message.role === 'user'
                              ? 'ml-6 bg-[#d97745] text-white'
                              : 'mr-6 border border-[rgba(223,210,188,.92)] bg-white text-[#5e4b39]'
                          }`}
                        >
                          <div className="mb-1 text-xs font-semibold uppercase tracking-[0.18em] opacity-75">
                            {message.role === 'user' ? 'You' : 'Agent'}
                          </div>
                          <div className="whitespace-pre-wrap">{message.content}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </div>

              <div className="mt-4 rounded-[24px] border border-[rgba(223,210,188,.92)] bg-[#fffdfa] p-5">
                <div className="grid gap-3 md:grid-cols-[220px_1fr] md:items-end">
                  <div className="space-y-2">
                    <Label>输入模式</Label>
                    <Select value={composerMode} onValueChange={(value) => setComposerMode(value as 'initial' | 'followup')}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="initial">首轮测试问题</SelectItem>
                        <SelectItem value="followup">继续追问</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="text-xs leading-6 text-[#7a6654]">
                    Use the dropdown to switch between the first bootstrapping prompt and later follow-up chat. This keeps the send button visible without resizing the browser.
                  </div>
                </div>
                <div className="mt-4 space-y-2">
                  <Label>{composerMode === 'initial' ? '首轮测试问题' : '继续追问'}</Label>
                  <Textarea
                    rows={4}
                    value={composerMode === 'initial' ? testPrompt : chatInput}
                    onChange={(event) => {
                      if (composerMode === 'initial') {
                        setTestPrompt(event.target.value);
                        if (!chatMessages.length) setChatInput(event.target.value);
                      } else {
                        setChatInput(event.target.value);
                      }
                    }}
                    onKeyDown={(event) => {
                      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                        event.preventDefault();
                        void runAgentTest();
                      }
                    }}
                    placeholder={
                      composerMode === 'initial'
                        ? 'Describe the currently loaded skill metadata, your role, and one concrete way you would use those skills.'
                        : 'Ask a follow-up question, for example: list the matched skills first, then explain whether you need to load a full SKILL.md body.'
                    }
                  />
                </div>
                <div className="mt-4 flex flex-wrap gap-3">
                  <Button className="bg-[#d97745] text-white hover:bg-[#c96532]" onClick={() => runAgentTest()} disabled={testingAgent}>
                    {testingAgent ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Wand2 className="mr-2 h-4 w-4" />}
                    {chatMessages.length ? '发送消息' : '开始测试'}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setChatMessages([]);
                      setChatInput(testPrompt);
                      setTestResult(null);
                      setComposerMode('initial');
                    }}
                    disabled={testingAgent}
                  >
                    重置对话
                  </Button>
                </div>
              </div>
            </div>

            <div className="min-h-0 rounded-[24px] border border-[rgba(223,210,188,.92)] bg-[#fffdfa] p-5">
              <div className="flex items-center gap-2 text-lg font-bold text-[#2f2318]"><CheckCircle2 className="h-5 w-5 text-[#d97745]" /> 测试结果</div>
              {!testResult ? (
                <div className="mt-5 rounded-2xl border border-dashed border-[rgba(214,194,162,.9)] bg-[#fff8f0] p-5 text-sm leading-7 text-[#7a6654]">
                  Run one test and this panel will show the effective provider/model, the returned answer, and the skill metadata that was loaded for the agent.
                </div>
              ) : (
                <ScrollArea className="mt-5 h-[calc(88vh-290px)] min-h-[260px] rounded-2xl border border-[rgba(232,220,201,.9)] bg-white p-4">
                  <div className="space-y-5 text-sm leading-7 text-[#5e4b39]">
                    <div>
                      <div className="font-semibold text-[#2f2318]">有效模型</div>
                      <div className="mt-2">{testResult.provider} / {testResult.model}</div>
                      {typeof testResult.conversation_count === 'number' ? (
                        <div className="mt-1 text-xs text-[#8a755f]">Current request messages: {testResult.conversation_count}</div>
                      ) : null}
                    </div>
                    <div>
                      <div className="font-semibold text-[#2f2318]">已加载 Skills 元数据</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {(testResult.loaded_skills || []).map((skill) => (
                          <span key={skill.slug} className="rounded-full bg-[#f6efe6] px-3 py-1 text-xs text-[#7b603f]">
                            {skill.name}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div className="font-semibold text-[#2f2318]">命中 Skills</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {(testResult.matched_skills || []).map((skill) => (
                          <span key={skill.slug} className="rounded-full bg-[#e7f6ed] px-3 py-1 text-xs text-[#2c8c59]">
                            {skill.name}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div className="font-semibold text-[#2f2318]">模型回复</div>
                      <pre className="mt-2 whitespace-pre-wrap rounded-2xl bg-[#f9f3eb] p-4 text-sm leading-7 text-[#5e4b39]">
                        {testResult.response || testResult.message || 'No response'}
                      </pre>
                    </div>
                  </div>
                </ScrollArea>
              )}
            </div>
          </div>
          <DialogFooter className="border-t border-[rgba(223,210,188,.92)] bg-white/80">
            <Button variant="outline" onClick={() => setTestDialogOpen(false)} disabled={testingAgent}>
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
