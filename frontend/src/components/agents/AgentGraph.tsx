"use client";

import { Check, X } from "lucide-react";
import { AGENT_META, SPECIALISTS } from "@/lib/agents";
import type { AgentKey, AgentRun, AgentStep } from "@/lib/types";

type NodeState = "idle" | "running" | "done" | "failed" | "skipped";

const W = 760;
const H = 250;
const SUP = { x: W / 2, y: 52 };
const ROW_Y = 190;

function nodeStates(run: AgentRun | undefined) {
  const steps = run?.steps ?? [];
  const states = Object.fromEntries(SPECIALISTS.map((k) => [k, "idle"])) as Record<AgentKey, NodeState>;
  const order: AgentKey[] = [];
  for (const step of steps) {
    if (step.agent === "supervisor") continue;
    states[step.agent] = step.status === "Running" ? "running" : step.status === "Failed" ? "failed" : "done";
    if (!order.includes(step.agent)) order.push(step.agent);
  }
  if (run && run.status !== "Running") {
    for (const k of SPECIALISTS) if (states[k] === "idle") states[k] = "skipped";
  }
  const supervisorThinking = steps.length > 0 && steps[steps.length - 1].agent === "supervisor" && steps[steps.length - 1].status === "Running";
  return { states, order, supervisorThinking };
}

const STROKE: Record<NodeState, string> = {
  idle: "#343a44",
  running: "#3987e5",
  done: "#199e70",
  failed: "#d03b3b",
  skipped: "#262b33",
};

export default function AgentGraph({ run, onSelect }: { run?: AgentRun; onSelect?: (step: AgentStep) => void }) {
  const { states, order, supervisorThinking } = nodeStates(run);
  const xs = SPECIALISTS.map((_, i) => 70 + i * ((W - 140) / (SPECIALISTS.length - 1)));
  const active = run?.status === "Running";

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="mx-auto w-full min-w-[620px] max-w-[880px]" role="img" aria-label="Agent routing graph">
        {/* edges */}
        {SPECIALISTS.map((key, i) => {
          const st = states[key];
          const visited = st === "done" || st === "running" || st === "failed";
          return (
            <path
              key={key}
              d={`M ${SUP.x} ${SUP.y + 24} C ${SUP.x} ${(SUP.y + ROW_Y) / 2}, ${xs[i]} ${(SUP.y + ROW_Y) / 2}, ${xs[i]} ${ROW_Y - 26}`}
              fill="none"
              stroke={visited ? STROKE[st] : "#262b33"}
              strokeWidth={visited ? 2 : 1}
              strokeDasharray={st === "running" ? "6 4" : st === "skipped" ? "2 4" : undefined}
              className={st === "running" ? "animate-dash" : undefined}
              opacity={st === "skipped" ? 0.6 : 1}
            />
          );
        })}

        {/* supervisor */}
        <g>
          <rect
            x={SUP.x - 78}
            y={SUP.y - 24}
            width={156}
            height={48}
            rx={10}
            fill="#1b1f26"
            stroke={active ? "#3987e5" : "#343a44"}
            strokeWidth={active ? 2 : 1}
            className={supervisorThinking ? "animate-pulse" : undefined}
          />
          <text x={SUP.x} y={SUP.y - 3} textAnchor="middle" className="fill-ink text-[13px] font-semibold">
            Supervisor
          </text>
          <text x={SUP.x} y={SUP.y + 13} textAnchor="middle" className="fill-ink-3 text-[10px]">
            {supervisorThinking ? "routing..." : active ? "orchestrating" : run ? "plan complete" : "waiting"}
          </text>
        </g>

        {/* specialists */}
        {SPECIALISTS.map((key, i) => {
          const st = states[key];
          const meta = AGENT_META[key];
          const Icon = meta.icon;
          const seq = order.indexOf(key);
          const step = run?.steps?.filter((s) => s.agent === key).at(-1);
          return (
            <g
              key={key}
              transform={`translate(${xs[i]}, ${ROW_Y})`}
              className={step && onSelect ? "cursor-pointer" : undefined}
              onClick={() => step && onSelect?.(step)}
              opacity={st === "skipped" ? 0.45 : 1}
            >
              <circle r={25} fill="#14171c" stroke={STROKE[st]} strokeWidth={st === "idle" || st === "skipped" ? 1 : 2} className={st === "running" ? "animate-pulse-ring" : undefined} />
              <foreignObject x={-10} y={-10} width={20} height={20}>
                <Icon className={st === "done" ? "size-5 text-[#3ec796]" : st === "running" ? "size-5 text-accent" : st === "failed" ? "size-5 text-critical" : "size-5 text-ink-3"} />
              </foreignObject>
              {seq >= 0 && (
                <g transform="translate(18,-20)">
                  <circle r={9} fill={STROKE[st]} />
                  <text textAnchor="middle" y={3.5} className="fill-white text-[10px] font-semibold">
                    {seq + 1}
                  </text>
                </g>
              )}
              {st === "done" && (
                <foreignObject x={-30} y={-28} width={12} height={12}>
                  <Check className="size-3 text-[#3ec796]" />
                </foreignObject>
              )}
              {st === "failed" && (
                <foreignObject x={-30} y={-28} width={12} height={12}>
                  <X className="size-3 text-critical" />
                </foreignObject>
              )}
              <text y={44} textAnchor="middle" className="fill-ink-2 text-[11px] font-medium">
                {meta.short}
              </text>
              <text y={58} textAnchor="middle" className="fill-ink-3 text-[10px]">
                {st === "skipped" ? "not needed" : st === "running" ? "working..." : step?.confidence != null ? `${step.confidence}% conf.` : st === "done" ? "done" : ""}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
