import types
import sys

import pytest

from app.services.llm.adapters.litellm_adapter import LiteLLMAdapter
from app.services.llm.types import LLMConfig, LLMMessage, LLMProvider, LLMRequest


class _FunctionDelta:
    def __init__(self, *, name=None, arguments=None):
        self.name = name
        self.arguments = arguments


class _ToolCallDelta:
    def __init__(self, *, index=0, id=None, type='function', function=None):
        self.index = index
        self.id = id
        self.type = type
        self.function = function


class _Delta:
    def __init__(self, *, content=None, tool_calls=None, reasoning_content=None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.reasoning_content = reasoning_content


class _DeltaWithExtra:
    def __init__(self, *, content=None, tool_calls=None, model_extra=None, additional_kwargs=None, provider_specific_fields=None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.model_extra = model_extra or {}
        self.additional_kwargs = additional_kwargs or {}
        self.provider_specific_fields = provider_specific_fields or {}


class _Choice:
    def __init__(self, *, delta=None, finish_reason=None):
        self.delta = delta or _Delta()
        self.finish_reason = finish_reason


class _Chunk:
    def __init__(self, *, choices=None, usage=None):
        self.choices = choices or []
        self.usage = usage


class _StreamResponse:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __aiter__(self):
        async def _gen():
            for chunk in self._chunks:
                yield chunk
        return _gen()


def test_litellm_sampling_parameters_are_omitted_in_auto_mode():
    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.MOONSHOT,
            api_key='test-key',
            model='kimi-k2.6',
        )
    )
    request = LLMRequest(messages=[LLMMessage(role='user', content='test')])

    assert adapter._sampling_kwargs(request) == {}


def test_litellm_sampling_parameters_use_explicit_config():
    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.MOONSHOT,
            api_key='test-key',
            model='kimi-k2.6',
            temperature=1,
            top_p=0.95,
        )
    )
    request = LLMRequest(messages=[LLMMessage(role='user', content='test')])

    assert adapter._sampling_kwargs(request) == {'temperature': 1, 'top_p': 0.95}


def test_litellm_sampling_parameters_omit_temperature_for_opus_4_8():
    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.CLAUDE,
            api_key='test-key',
            model='claude-opus-4-8',
            temperature=0.1,
        )
    )
    request = LLMRequest(messages=[LLMMessage(role='user', content='test')])

    assert adapter._sampling_kwargs(request) == {}


@pytest.mark.asyncio
async def test_litellm_adapter_stream_complete_emits_tool_call_before_done(monkeypatch):
    async def fake_acompletion(**kwargs):
        assert kwargs['stream'] is True
        assert kwargs['tools'][0]['function']['name'] == 'Read'
        return _StreamResponse([
            _Chunk(choices=[_Choice(delta=_Delta(content='Need '))]),
            _Chunk(
                choices=[
                    _Choice(
                        delta=_Delta(
                            tool_calls=[
                                _ToolCallDelta(
                                    index=0,
                                    id='call_1',
                                    function=_FunctionDelta(name='Read', arguments='{"file_path":"README'),
                                )
                            ]
                        )
                    )
                ]
            ),
            _Chunk(
                choices=[
                    _Choice(
                        delta=_Delta(
                            tool_calls=[
                                _ToolCallDelta(
                                    index=0,
                                    function=_FunctionDelta(arguments='.md"}'),
                                )
                            ]
                        ),
                        finish_reason='tool_calls',
                    )
                ],
                usage=types.SimpleNamespace(prompt_tokens=12, completion_tokens=7, total_tokens=19),
            ),
        ])

    fake_litellm = types.SimpleNamespace(
        acompletion=fake_acompletion,
        cache=None,
        drop_params=False,
        exceptions=types.SimpleNamespace(
            AuthenticationError=Exception,
            RateLimitError=Exception,
            APIConnectionError=Exception,
            APIError=Exception,
        ),
    )
    monkeypatch.setitem(sys.modules, 'litellm', fake_litellm)

    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key='test-key',
            model='gpt-4o-mini',
        )
    )
    request = LLMRequest(
        messages=[LLMMessage(role='user', content='inspect')],
        tools=[
            {
                'type': 'function',
                'function': {
                    'name': 'Read',
                    'description': 'Read a file',
                    'parameters': {'type': 'object', 'properties': {}},
                },
            }
        ],
        parallel_tool_calls=True,
        stream=True,
    )

    events = []
    async for event in adapter.stream_complete(request):
        events.append(event)

    assert [event['type'] for event in events] == ['token', 'tool_call', 'done']
    assert events[1]['tool_call']['name'] == 'Read'
    assert events[1]['tool_call']['arguments'] == '{"file_path":"README.md"}'
    assert events[2]['finish_reason'] == 'tool_calls'
    assert events[2]['usage']['total_tokens'] == 19


@pytest.mark.asyncio
async def test_litellm_adapter_stream_complete_accumulates_reasoning_content(monkeypatch):
    async def fake_acompletion(**kwargs):
        assert kwargs['stream'] is True
        return _StreamResponse([
            _Chunk(choices=[_Choice(delta=_Delta(reasoning_content='Need the '))]),
            _Chunk(choices=[_Choice(delta=_Delta(reasoning_content='skill first.'))]),
            _Chunk(
                choices=[
                    _Choice(
                        delta=_Delta(
                            tool_calls=[
                                _ToolCallDelta(
                                    index=0,
                                    id='call_1',
                                    function=_FunctionDelta(name='Skill', arguments='{"skill_ref":"code-audit-finding"}'),
                                )
                            ]
                        ),
                        finish_reason='tool_calls',
                    )
                ]
            ),
        ])

    fake_litellm = types.SimpleNamespace(
        acompletion=fake_acompletion,
        cache=None,
        drop_params=False,
        exceptions=types.SimpleNamespace(
            AuthenticationError=Exception,
            RateLimitError=Exception,
            APIConnectionError=Exception,
            APIError=Exception,
        ),
    )
    monkeypatch.setitem(sys.modules, 'litellm', fake_litellm)

    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            api_key='test-key',
            model='deepseek-v4-pro',
        )
    )
    request = LLMRequest(
        messages=[LLMMessage(role='user', content='inspect')],
        tools=[{'type': 'function', 'function': {'name': 'Skill', 'parameters': {'type': 'object'}}}],
        stream=True,
    )

    events = []
    async for event in adapter.stream_complete(request):
        events.append(event)

    assert [event['type'] for event in events] == ['reasoning_delta', 'reasoning_delta', 'tool_call', 'done']
    assert events[0]['reasoning_content'] == 'Need the '
    assert events[-1]['reasoning_content'] == 'Need the skill first.'
    assert events[-1]['tool_calls'][0]['id'] == 'call_1'


@pytest.mark.asyncio
async def test_litellm_adapter_stream_complete_accumulates_reasoning_content_from_extra_fields(monkeypatch):
    async def fake_acompletion(**kwargs):
        assert kwargs['stream'] is True
        return _StreamResponse([
            _Chunk(choices=[_Choice(delta=_DeltaWithExtra(model_extra={'reasoning_content': 'Need '}))]),
            _Chunk(choices=[_Choice(delta=_DeltaWithExtra(additional_kwargs={'reasoning_content': 'native '}))]),
            _Chunk(choices=[_Choice(delta=_DeltaWithExtra(provider_specific_fields={'reasoning_content': 'history.'}))]),
            _Chunk(
                choices=[
                    _Choice(
                        delta=_DeltaWithExtra(
                            tool_calls=[
                                _ToolCallDelta(
                                    index=0,
                                    id='call_1',
                                    function=_FunctionDelta(name='Skill', arguments='{"skill_ref":"code-audit-finding"}'),
                                )
                            ]
                        ),
                        finish_reason='tool_calls',
                    )
                ]
            ),
        ])

    fake_litellm = types.SimpleNamespace(
        acompletion=fake_acompletion,
        cache=None,
        drop_params=False,
        exceptions=types.SimpleNamespace(
            AuthenticationError=Exception,
            RateLimitError=Exception,
            APIConnectionError=Exception,
            APIError=Exception,
        ),
    )
    monkeypatch.setitem(sys.modules, 'litellm', fake_litellm)

    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            api_key='test-key',
            model='deepseek-reasoner',
        )
    )
    request = LLMRequest(
        messages=[LLMMessage(role='user', content='inspect')],
        tools=[{'type': 'function', 'function': {'name': 'Skill', 'parameters': {'type': 'object'}}}],
        stream=True,
    )

    events = []
    async for event in adapter.stream_complete(request):
        events.append(event)

    assert [event['type'] for event in events] == [
        'reasoning_delta',
        'reasoning_delta',
        'reasoning_delta',
        'tool_call',
        'done',
    ]
    assert events[-1]['reasoning_content'] == 'Need native history.'


@pytest.mark.asyncio
async def test_litellm_adapter_stream_complete_preserves_empty_unknown_exception_details(monkeypatch):
    class AuthenticationError(Exception):
        pass

    class RateLimitError(Exception):
        pass

    class APIConnectionError(Exception):
        pass

    class EmptyStreamError(Exception):
        def __str__(self):
            return ''

    async def fake_acompletion(**kwargs):
        raise EmptyStreamError()

    fake_litellm = types.SimpleNamespace(
        acompletion=fake_acompletion,
        cache=None,
        drop_params=False,
        exceptions=types.SimpleNamespace(
            AuthenticationError=AuthenticationError,
            RateLimitError=RateLimitError,
            APIConnectionError=APIConnectionError,
            APIError=Exception,
        ),
    )
    monkeypatch.setitem(sys.modules, 'litellm', fake_litellm)

    adapter = LiteLLMAdapter(
        LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key='test-key',
            model='gpt-4o-mini',
        )
    )
    request = LLMRequest(
        messages=[LLMMessage(role='user', content='inspect')],
        stream=True,
    )

    events = []
    async for event in adapter.stream_complete(request):
        events.append(event)

    assert [event['type'] for event in events] == ['error']
    assert events[0]['error_type'] == 'unknown'
    assert events[0]['error_class'] == 'EmptyStreamError'
    assert 'EmptyStreamError' in events[0]['error']
