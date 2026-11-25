# Cost and usage model

## Evidence priority

Use cost evidence in this order:

1. Final invoices and contracted rate cards supplied by the user.
2. Historical/billable cost APIs.
3. Estimated and projected cost APIs.
4. Product usage APIs and estimated-usage metrics.
5. Public list prices, clearly labeled as scenario assumptions.

Never multiply a public price by usage and label the result as the customer's actual bill. Taxes, commitments, tiers, minimums, credits, overages, bundles, and negotiated rates can materially change cost.

## Baseline dimensions

Report monthly and, where possible, 3/6/12-month trends by product and organization/account:

- infrastructure hosts, containers/tasks, serverless functions, network devices;
- custom metric names/points or indexed metric time series and resolution;
- APM hosts/containers, analyzed spans, ingested spans/bytes, indexed spans, profiling;
- logs ingested, indexed/scanned, retention by index, rehydration and archives;
- RUM sessions/events, session replay, synthetics API/browser/mobile tests;
- CI visibility, DBM, NPM, CSPM/SIEM, LLM observability, and other licensed products;
- support, platform commitments, credits, and shared-contract items when supplied.

Datadog usage and cost data can be delayed. Preserve the API timestamp and delay note in the report.

Authoritative source references:

- Datadog Usage Metering API: https://docs.datadoghq.com/api/latest/usage-metering/
- Datadog estimated cost API: https://docs.datadoghq.com/api/latest/usage-metering/get-estimated-cost-across-your-account/
- Datadog cost details: https://docs.datadoghq.com/account_management/plan_and_usage/cost_details/
- Datadog estimated usage metrics: https://docs.datadoghq.com/account_management/billing/usage_metrics/

## Unit economics

Calculate only when numerator and denominator periods match:

- cost per active service;
- cost per host/container;
- cost per million metric points or per 1,000 MTS;
- cost per GB logs ingested and indexed;
- cost per million spans or trace-analyzed unit;
- cost per synthetic test run;
- cost per environment, cluster, namespace, or team when allocation tags support it.

Use `unallocated` for spend that cannot be mapped to an owner. Do not force allocation using weak tag inference.

## Target scenarios

For each target, model at least:

- `as_is`: migrate current volume and retention without optimization;
- `optimized`: remove approved stale/duplicate assets, filter low-value logs, control cardinality, and apply sampling;
- `growth`: optimized baseline plus stated growth assumptions;
- `dual_run`: temporary source + target + collector/gateway overhead during validation.

Show formula, units, rate source/date, commitment assumptions, and low/base/high range. Keep one-time migration labor separate from recurring platform spend.

## Savings guardrails

Savings are not valid if they rely on dropping required compliance retention, SLO coverage, incident response capability, or telemetry needed for contractual obligations. State capability loss next to any cost reduction.
