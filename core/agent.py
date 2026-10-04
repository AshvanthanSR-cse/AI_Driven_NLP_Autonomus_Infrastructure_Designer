"""Agent loop: the LLM chooses tools, code executes them.

- max 5 tool rounds per request
- arguments validated with pydantic; one chance for the model to fix bad JSON/arguments
- write tools only save a script to the Scripts page (user runs or schedules it there)
- keyword fallback router when the model calls no tool, picks a known-wrong tool, or LM Studio is down
"""
import json
from dataclasses import dataclass, field

from core import llm, router, tools
from core.config import settings
from core.tools import ToolContext, ToolError

SYSTEM_PROMPT = f"""You are CloudAI, an assistant that manages the user's AWS account (region {settings.aws_region}).
You can only act through the provided tools. Rules:
- Always call a tool to get facts. Never invent instance IDs, names, costs, times or numbers.
- Copy numbers, times and IDs exactly as the tool returned them. Never do date, time, timezone or cost arithmetic yourself; the tools already did it.
- Always say the timezone when you mention times. The user's timezone is {settings.app_timezone}.
- For any change to AWS (stop, start, create, tag, delete...) call stop_instance, start_instance or aws_write. These do NOT change anything: they save a script on the Scripts page. Tell the user the script number and that they must open it on the Scripts page, read it and click Approve (or Deny, or edit it); after approving they can Run now or Schedule. Never say the change was made.
- To BUILD infrastructure (a VPC with subnets / NAT gateway / internet gateway / route tables, or a new EC2 instance) call plan_task with the template and ONLY the details the user actually said; never invent values. If it returns QUESTIONS NEEDED, ask the user those questions in a short numbered list with the options, and say they can also use the form below. Do not answer the questions yourself.
- For an ALB/load balancer URL use list_load_balancers. To extract or download Lambda code use download_lambda_code and tell the user the local folder.
- If a tool returns an error, explain it briefly and suggest what the user can do.
- Lambda does not store schedules. For questions about when functions run, use list_scheduled_lambdas.
- Some things need a human and cannot be automated: account creation, MFA, support cases, Marketplace subscriptions, quota increases. Say so.
- Be concise. Use a short markdown table for lists.
/no_think"""

QUESTIONS_NOTE = ("QUESTIONS NEEDED before the script for {title} can be written. Nothing was saved. Ask the user "
                  "these questions (numbered, with the options shown); the app also shows a form:\n{questions}\n{notes}")

SCRIPT_NOTE = ("SCRIPT SAVED: #{id} '{title}'{warn}. Nothing has run yet. Tell the user to open it on the "
               "Scripts page, read it and click Approve or Deny; after approving they can Run now or Schedule.")


@dataclass
class AgentResult:
    text: str
    scripts: list[dict] = field(default_factory=list)   # saved scripts: {id, title, destructive, risk}
    tools_used: list[str] = field(default_factory=list)
    used_fallback: bool = False
    llm_available: bool = True
    questions: dict | None = None    # a task template needs answers from the user


class _Run:
    def __init__(self, ctx: ToolContext, route):
        self.ctx = ctx
        self.route = route
        self.scripts: list[dict] = []
        self.tools_used: list[str] = []
        self.bad_args: dict[str, int] = {}
        self.used_fallback = False
        self.last_result = None
        self.questions: dict | None = None

    def execute(self, name: str, raw_args) -> str:
        """Validate and run one tool call; return the text the LLM sees."""
        # Known failure mode: model picks a generic tool when a strong keyword route exists.
        if (self.route and self.route[0] in router.STRONG_ROUTES and name != self.route[0]
                and name in tools.REGISTRY and not tools.REGISTRY[name].is_write):
            name, raw_args = self.route
            self.used_fallback = True
        try:
            args = tools.validate_args(name, raw_args)
        except ToolError as e:
            self.bad_args[name] = self.bad_args.get(name, 0) + 1
            if self.bad_args[name] == 1:
                return f"ERROR: {e}. Fix the arguments and call the tool again."
            if self.route:  # second failure: fall back to the router's choice
                name, raw_args = self.route
                self.used_fallback = True
                args = tools.validate_args(name, raw_args)
            else:
                return f"ERROR: {e}. Do not call this tool again; explain the problem to the user."
        self.tools_used.append(name)
        tool = tools.REGISTRY[name]
        try:
            if tool.is_write:
                saved = tools.create_script(name, args, self.ctx)
                if "questions" in saved:
                    self.questions = saved["questions"]
                    return QUESTIONS_NOTE.format(title=self.questions["title"],
                                                 questions=format_questions(self.questions),
                                                 notes="\n".join(self.questions["notes"]))
                self.scripts.append(saved)
                warn = " (DESTRUCTIVE: needs a typed confirmation)" if saved["destructive"] else ""
                return SCRIPT_NOTE.format(id=saved["id"], title=saved["title"], warn=warn)
            data = tools.run_read_tool(name, args, self.ctx)
            self.last_result = (name, data)
            return tools.to_llm_text(data)
        except ToolError as e:
            return f"ERROR: {e}"
        except Exception as e:  # e.g. vault/DB problems; keep the message safe
            return f"ERROR: {type(e).__name__}: {str(e)[:200]}"

    def result(self, text: str, llm_ok: bool = True) -> AgentResult:
        return AgentResult(text=text, scripts=self.scripts, tools_used=self.tools_used,
                           used_fallback=self.used_fallback, llm_available=llm_ok, questions=self.questions)


def format_questions(q: dict) -> str:
    lines = []
    for n, item in enumerate(q["questions"], 1):
        line = f"{n}. {item['question']}"
        if item.get("options"):
            line += " Options: " + "; ".join(str(o["label"]) for o in item["options"][:8])
        if item.get("default") not in (None, "", []):
            line += f" (suggested: {item['default']})"
        if item.get("error"):
            line += f" PROBLEM: {item['error']}"
        lines.append(line)
    return "\n".join(lines)


def run(user_text: str, ctx: ToolContext, history: list[dict] | None = None,
        pending_task: dict | None = None) -> AgentResult:
    """Answer one user request. history = earlier [{'role': 'user'|'assistant', 'content': str}].
    pending_task = the questions payload of a task template the user may be answering now."""
    ctx.request = user_text
    ctx.pending_task = pending_task
    route = None if pending_task else router.route(user_text)
    state = _Run(ctx, route)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += [m for m in (history or [])[-10:] if m.get("role") in ("user", "assistant") and m.get("content")]
    if pending_task:
        messages.append({"role": "system", "content": (
            f"The user was asked questions for plan_task template '{pending_task['template']}'. Known so far: "
            f"{json.dumps(pending_task['inputs'], default=str)}. Open questions:\n{format_questions(pending_task)}\n"
            "If the next message answers any of them, call plan_task with that template and put ONLY the values "
            "the user gave now in inputs, using the option values (the app merges them with what is known). If the "
            "user accepts the suggestions, pass the suggested values. If the user talks about something else, "
            "ignore this.")})
    messages.append({"role": "user", "content": user_text})
    specs = tools.openai_tool_specs()

    try:
        for round_no in range(settings.max_tool_rounds):
            msg = llm.chat(messages, specs)
            calls = msg.tool_calls or []
            if not calls:
                if round_no == 0 and route and not state.tools_used:
                    # Model answered without data: run the routed tool and let it explain the result.
                    state.used_fallback = True
                    name, args = route
                    call_id = "fallback-0"
                    messages.append({"role": "assistant", "content": "", "tool_calls": [
                        {"id": call_id, "type": "function",
                         "function": {"name": name, "arguments": json.dumps(args)}}]})
                    messages.append({"role": "tool", "tool_call_id": call_id,
                                     "content": state.execute(name, args)})
                    continue
                return state.result(msg.content or "(no answer)")
            messages.append({
                "role": "assistant", "content": msg.content or "",
                "tool_calls": [{"id": c.id, "type": "function",
                                "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"}}
                               for c in calls],
            })
            for c in calls:
                messages.append({"role": "tool", "tool_call_id": c.id,
                                 "content": state.execute(c.function.name, c.function.arguments)})
        # Out of rounds: ask for a final answer without tools.
        final = llm.chat(messages + [{"role": "user", "content": "Answer now using the tool results above."}])
        return state.result(final.content or "(no answer)")
    except Exception as e:
        if not _is_llm_error(e):
            raise
        return _offline_answer(state, route, e)


def _is_llm_error(e: Exception) -> bool:
    import openai
    return isinstance(e, (openai.APIConnectionError, openai.APITimeoutError, openai.APIStatusError))


def _offline_answer(state: _Run, route, err: Exception) -> AgentResult:
    """LM Studio unavailable: answer with the routed tool's raw result, formatted by code."""
    head = f"LM Studio is not reachable ({type(err).__name__}), so the AI explanation is unavailable."
    if state.last_result:
        name, data = state.last_result
    elif route:
        state.used_fallback = True
        text = state.execute(*route)
        if text.startswith(("ERROR", "SCRIPT")):
            return state.result(f"{head}\n\n{text}", llm_ok=False)
        name, data = state.last_result
    else:
        return state.result(f"{head} I could not match your request to a tool by keywords either.",
                            llm_ok=False)
    return state.result(f"{head} Raw result from `{name}`:\n\n{format_plain(data)}", llm_ok=False)


def format_plain(data, max_rows: int = 30) -> str:
    """Code-only markdown rendering of a tool result (used when the LLM is offline)."""
    if not isinstance(data, dict):
        return f"```\n{tools.to_llm_text(data)}\n```"
    lines, tables = [], []
    for k, v in data.items():
        if isinstance(v, list) and v and all(isinstance(r, dict) for r in v):
            tables.append((k, v))
        elif isinstance(v, list):
            lines.append(f"- **{k}**: {', '.join(map(str, v)) if v else 'none'}")
        elif not isinstance(v, dict):
            lines.append(f"- **{k}**: {v}")
    out = "\n".join(lines)
    for k, rows in tables:
        cols = list(dict.fromkeys(c for r in rows for c in r))
        cell = lambda x: (", ".join(map(str, x)) if isinstance(x, list) else str(x if x is not None else "")
                          ).replace("|", "\\|")
        out += f"\n\n**{k}**\n\n| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
        out += "\n".join("| " + " | ".join(cell(r.get(c)) for c in cols) + " |" for r in rows[:max_rows])
        if len(rows) > max_rows:
            out += f"\n\n... {len(rows) - max_rows} more"
    return out.strip()
