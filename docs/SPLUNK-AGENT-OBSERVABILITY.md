# Splunk Agent Observability (AI agent observability)

Splunk Agent Observability is a **separate product from Splunk Observability Cloud**,
with its own console, its own API key and its own OTLP endpoint. It is where GenAI and
agentic telemetry — LLM calls, tool executions, retrievals, agent trajectories — is
traced and evaluated. Its docs live at <https://agent-observability-docs.splunk.com>.

This repo sends GenAI spans to both places: full traces to Splunk APM (so you can see
the agent in the context of the rest of the Astronomy Shop), and the GenAI spans alone
to Agent Observability.

## Where the spans come from

OpenTelemetry Demo v3.0.0 ships three GenAI services:

| Service | What it is |
|---|---|
| `agent` | FastAPI + LangGraph ReAct agent, instrumented with the Traceloop SDK |
| `chatbot` | Gradio chat UI at `/chatbot` that calls the agent |
| `mcp` | Model Context Protocol server exposing shop operations as tools |

They emit Traceloop/OpenLLMetry attributes. The demo's collector normalizes those into
OpenTelemetry GenAI semantic conventions with upstream's **`gen_ai_normalizer`**
processor — which is exactly what Agent Observability's OTLP provider expects.

By default the agent runs with `USE_VCR=True` and replays recorded LLM responses from
the chart's cassettes, so **no model credentials and no spend are required**. The spans
are real; the model responses are recorded.

Nothing in the demo drives the agent on its own, so this repo adds a small
`ai-load-generator` Deployment ([manifests/ai-load-generator.yaml](../manifests/ai-load-generator.yaml))
that POSTs to `agent:8010/prompt` on a loop, cycling the three prompts the cassettes
cover. Set `AI_LOAD_ENABLED=false` to turn it off and drive the agent by hand at
<http://localhost:8080/chatbot>.

## The branch

```yaml
traces/splunk_ao:
  receivers:  [otlp]
  processors: [memory_limiter, resourcedetection, resource, resource/deployment_env,
               gen_ai_normalizer, filter/genai, transform/splunk_ao, batch]
  exporters:  [otlphttp/splunk_ao]
```

It is a second pipeline off the same OTLP receiver, not a tee off the APM pipeline.
If the Agent Observability endpoint is unreachable, APM is unaffected.

**`filter/genai`** drops everything that is not a GenAI span:

```yaml
- 'attributes["gen_ai.operation.name"] == nil and
   attributes["gen_ai.provider.name"]  == nil and
   attributes["gen_ai.system"]         == nil and
   attributes["openinference.span.kind"] == nil'
```

Both convention families are checked because Agent Observability accepts either
OpenTelemetry GenAI semconv *or* OpenInference. Anything carrying a marker from either
passes; HTTP, gRPC and database spans do not.

**`transform/splunk_ao`** sets the resource attributes the backend uses for routing:

```yaml
splunk_ao.project.name     = SPLUNK_AO_PROJECT
splunk_ao.agentstream.name = SPLUNK_AO_AGENT_STREAM
```

**`otlphttp/splunk_ao`** posts protobuf OTLP to `<api-url>/otel/v1/traces` with:

| Header | From |
|---|---|
| `Splunk-AO-API-Key` | `SPLUNK_AO_API_KEY`, via the `otel-demo-destinations` Secret |
| `project` | `SPLUNK_AO_PROJECT` |
| `agentstream` | `SPLUNK_AO_AGENT_STREAM` |

`Content-Type: application/x-protobuf` is what `otlphttp` sends by default, which is
what the endpoint requires.

## Configuration

```bash
SPLUNK_AO_API_KEY="..."
SPLUNK_AO_API_URL="https://api.splunk-ao.splunk.com"   # self-hosted: your console URL
SPLUNK_AO_PROJECT="otel-demo"
SPLUNK_AO_AGENT_STREAM="astronomy-shop"
```

For a self-hosted or standalone deployment, set `SPLUNK_AO_API_URL` to your console URL
— the renderer appends `/otel/v1/traces` itself. Create the project and agent stream in
the console first; the headers reference them by name.

## What a valid span needs

Agent Observability validates spans per type. The demo's Traceloop instrumentation plus
`gen_ai_normalizer` covers this, but it is what to check if spans arrive and then get
rejected:

| Span type | Required |
|---|---|
| Agent | `gen_ai.operation.name` (`invoke_agent`), `gen_ai.provider.name`, span name `invoke_agent {agent}`, input + output messages |
| LLM | `gen_ai.operation.name` (`chat`), `gen_ai.provider.name`, `gen_ai.request.model`, input + output messages |
| Tool | `gen_ai.operation.name` = `execute_tool`, `gen_ai.tool.name`, arguments + result |
| Retriever | `db.operation` = `query` or `search`, query input, document list output |

Errored spans must carry `error.type` **and** span status `ERROR`.

Input/output can use either `gen_ai.input.messages` / `gen_ai.output.messages`
(OpenTelemetry) or `input.value` / `output.value` (OpenInference).

## Verifying

```bash
# Are GenAI spans being produced at all?
kubectl logs -n otel-demo deploy/ai-load-generator --tail=20

# Is the branch exporting, or erroring?
kubectl logs -n otel-demo -l app.kubernetes.io/name=opentelemetry-collector --tail=200 \
  | grep -i splunk_ao
```

A `401` means the API key is wrong. A `4xx` with `partialSuccess` in the body means
spans arrived but failed validation — compare against the table above. Silence, with the
`ai-load-generator` logging `status=200`, means the filter dropped everything: check
that the `agent` pod is actually emitting `gen_ai.*` attributes with
`COLLECTOR_DEBUG_EXPORTER=true`.

## Relationship to Splunk Observability Cloud

These are complementary, not alternatives:

| | Splunk Observability Cloud (APM) | Splunk Agent Observability |
|---|---|---|
| Scope | Every service, full distributed traces | GenAI/agentic spans |
| Question | "Is checkout slow, and where?" | "Did the agent pick the right tool, and was the answer grounded?" |
| Auth | Org access token, `X-SF-Token` | API key, `Splunk-AO-API-Key` |
| Endpoint | `ingest.<realm>.observability.splunkcloud.com` | `<console-url>/otel/v1/traces` |

They can be enabled independently. Configuring only `SPLUNK_AO_API_KEY` gives you the
GenAI branch and nothing else.
