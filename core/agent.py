"""Agent loop: the LLM chooses tools, code executes them.

- max 5 tool rounds per request
- arguments validated with pydantic; one chance for the model to fix bad JSON/arguments
- write tools only save a script to the Scripts page (user runs or schedules it there)
- keyword fallback router when the model calls no tool, picks a known-wrong tool, or LM Studio is down
"""
import json
from dataclasses import dataclass, field

from core import llm, prereqs, router, tools
from core.config import settings
from core.tools import ToolContext, ToolError

SYSTEM_PROMPT = f"""You are Kintsugi, an assistant that manages the user's AWS account (region {settings.aws_region}).
You can only act through the provided tools. Rules:
- Always call a tool to get facts. Never invent instance IDs, names, costs, times or numbers.
- Copy numbers, times and IDs exactly as the tool returned them. Never do date, time, timezone or cost arithmetic yourself; the tools already did it.
- Always say the timezone when you mention times. The user's timezone is {settings.app_timezone}.
- For any change to AWS (stop, start, create, tag, delete...) call stop_instance, start_instance or aws_write. These do NOT change anything: they save a script on the Scripts page. Tell the user the script number and that they must open it on the Scripts page, read it and click Approve (or Deny, or edit it); after approving they can Run now or Schedule. Never say the change was made.
- PREREQUISITES: before building or creating anything with a service that has no plan_task recipe (Db2/Oracle/SQL Server are in the database recipe; others like Neptune, Redshift, OpenSearch, MSK, EFS ...), or when the user asks what is needed, call check_prerequisites first. plan_task checks prerequisites itself. If a result says PREREQUISITES MISSING, show the checklist exactly (keep the icons), tell the user to create the missing items first (the "How" text says how), and that they can click "Check again". Never call aws_write to create the missing items unless the user asks for that.
- To BUILD or DEPLOY in several steps call plan_task: database (RDS PostgreSQL/MySQL/MariaDB/SQL Server/Oracle/Db2, Aurora, DynamoDB, DocumentDB, Redis/Valkey/Memcached; if the user names any advanced setting such as Multi-AZ, replicas, backups, version, IOPS, indexes, pass settings="custom" plus only those keys), VPC network, EC2 instance, IAM role, Lambda from a local folder, Docker image to ECR, Dockerfile app on ECS Fargate, EKS cluster (+ app), Jenkins server, deploy a website folder with Ansible, run the user's Ansible playbook, run the user's Terraform folder. Pass ONLY the details the user actually said (copy folder paths exactly); never invent values. If it returns QUESTIONS NEEDED, ask the user those questions in a short numbered list with the options, and say they can also use the form below. Do not answer the questions yourself.
- The user can ATTACH local files/folders; you see only their paths, never their contents. Use the attached path exactly. "Put this in S3 / bucket X" -> plan_task s3_upload (private, pass bucket if named). A PUBLIC bucket, a static website / index.html hosted on S3, or "public access" + S3 -> plan_task s3_static_website (it turns off Block Public Access, adds a public-read policy, website hosting and versioning); never use s3_upload for that. A Dockerfile -> ecs_fargate_service, eks_cluster or docker_image. A folder -> ansible_website, lambda_function or terraform_project as asked.
- S3 files: list_s3_objects to see what is in a bucket, download_s3_object to save a file locally.
- Azure and Google Cloud (basic): list_cloud_vms, list_cloud_storage, cloud_vm_action (start/stop, saved as a script), cloud_upload. Everything else is AWS.
- IAM changes (users, roles, policies) are allowed through aws_write or plan_task iam_role; they always need a typed confirmation. Creating access keys or passwords and granting AdministratorAccess are blocked: tell the user to do those in the IAM console.
- For an ALB/load balancer URL use list_load_balancers. To extract or download Lambda code use download_lambda_code and tell the user the local folder.
- If a tool returns an error, explain it briefly and suggest what the user can do.
- Lambda does not store schedules. For questions about when functions run, use list_scheduled_lambdas.
- Some things need a human and cannot be automated: account creation, MFA, support cases, Marketplace subscriptions, quota increases. Say so.
- Every new request is a NEW task. Never carry names, buckets, policies, paths or settings from an earlier, finished task into a new one unless the user clearly refers to it ("that bucket", "the same role").
- Be concise. Use a short markdown table for lists.
/no_think"""

QUESTIONS_NOTE = ("QUESTIONS NEEDED before the script for {title} can be written. Nothing was saved. Ask the user "
                  "these questions (numbered, with the options shown); the app also shows a form:\n{questions}\n{notes}")

PREREQ_NOTE = ("PREREQUISITES {state}. Nothing was saved. Show the user this checklist exactly (keep the icons and "
               "the How text) and tell them to create missing items first; the app also shows it as a card with "
               "a 'Check again' button:\n{checklist}")

SCRIPT_NOTE = ("SCRIPT SAVED: #{id} '{title}'{warn}. Nothing has run yet. Tell the user to open it on the "
               "Scripts page, read it and click Approve or Deny; after approving they can Run now or Schedule.")


@dataclass
class AgentResult:
    text: str
    scripts: list[dict] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    used_fallback: bool = False
    llm_available: bool = True
    questions: dict | None = None
    prerequisites: dict | None = None


class _NewTask(Exception):
    """The model started a different plan_task while earlier chat was in context: plan it again without that chat."""


class _Run:
    def __init__(self, ctx: ToolContext, route, isolate_new_tasks: bool = False):
        self.isolate_new_tasks = isolate_new_tasks
        self.ctx = ctx
        self.route = route
        self.scripts: list[dict] = []
        self.tools_used: list[str] = []
        self.bad_args: dict[str, int] = {}
        self.used_fallback = False
        self.last_result = None
        self.questions: dict | None = None
        self.prerequisites: dict | None = None

    def execute(self, name: str, raw_args) -> str:
        """Validate and run one tool call; return the text the LLM sees."""
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
            if self.route:
                name, raw_args = self.route
                self.used_fallback = True
                args = tools.validate_args(name, raw_args)
            else:
                return f"ERROR: {e}. Do not call this tool again; explain the problem to the user."
        if self.isolate_new_tasks and name == "plan_task" and not self.scripts and not self.questions:
            pending = self.ctx.pending_task
            if not pending or pending.get("template") != args.template:
                raise _NewTask()
        self.tools_used.append(name)
        tool = tools.REGISTRY[name]
        try:
            if tool.is_write:
                saved = tools.create_script(name, args, self.ctx)
                if "prerequisites" in saved:
                    self.prerequisites = saved["prerequisites"]
                    return PREREQ_NOTE.format(state="MISSING", checklist=prereqs.format_report(self.prerequisites))
                if "questions" in saved:
                    if saved["questions"].get("prerequisites"):
                        self.prerequisites = saved["questions"]["prerequisites"]
                    self.questions = saved["questions"]
                    return QUESTIONS_NOTE.format(title=self.questions["title"],
                                                 questions=format_questions(self.questions),
                                                 notes="\n".join(self.questions["notes"]) + (
                                                     "\n" + prereqs.format_report(self.prerequisites)
                                                     if self.questions.get("prerequisites") else ""))
                self.scripts.append(saved)
                warn = " (DESTRUCTIVE: needs a typed confirmation)" if saved["destructive"] else ""
                return SCRIPT_NOTE.format(id=saved["id"], title=saved["title"], warn=warn)
            data = tools.run_read_tool(name, args, self.ctx)
            self.last_result = (name, data)
            if name == "check_prerequisites":
                self.prerequisites = data
                return PREREQ_NOTE.format(state="MISSING" if data["blocking"] else "CHECKED",
                                          checklist=data["checklist"])
            return tools.to_llm_text(data)
        except ToolError as e:
            return f"ERROR: {e}"
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {str(e)[:200]}"

    def result(self, text: str, llm_ok: bool = True) -> AgentResult:
        return AgentResult(text=text, scripts=self.scripts, tools_used=self.tools_used,
                           used_fallback=self.used_fallback, llm_available=llm_ok, questions=self.questions,
                           prerequisites=self.prerequisites)


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


def attachments_note(attachments: list[dict]) -> str:
    lines = [f"{n}. {a['path']} ({a['kind']}, {a['type']}"
             + (f", {a['size_mb']} MB" if a["kind"] == "file" else "") + ")"
             for n, a in enumerate(attachments, 1)]
    return ("The user attached these local files/folders with this message (paths only; contents are not shown "
            "to you). Use these exact paths:\n" + "\n".join(lines))


def run(user_text: str, ctx: ToolContext, history: list[dict] | None = None,
        pending_task: dict | None = None, attachments: list[dict] | None = None) -> AgentResult:
    """Answer one user request. history = earlier [{'role': 'user'|'assistant', 'content': str}].
    pending_task = the questions payload of a task template the user may be answering now.
    attachments = files/folders attached in chat ([{path, kind, type, size_mb}]); only paths reach the LLM."""
    history = [m for m in (history or [])[-10:] if m.get("role") in ("user", "assistant") and m.get("content")]
    if history or pending_task:
        try:
            return _run(user_text, ctx, history, pending_task, attachments, isolate_new_tasks=True)
        except _NewTask:
            pass
    return _run(user_text, ctx, [], None, attachments)


def _run(user_text: str, ctx: ToolContext, history: list[dict], pending_task: dict | None,
         attachments: list[dict] | None, isolate_new_tasks: bool = False) -> AgentResult:
    ctx.request = user_text
    ctx.pending_task = pending_task
    ctx.attachments = attachments or None
    route = None if pending_task else router.route(user_text, attachments)
    state = _Run(ctx, route, isolate_new_tasks)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += history
    if pending_task:
        messages.append({"role": "system", "content": (
            f"The user was asked questions for plan_task template '{pending_task['template']}'. Known so far: "
            f"{json.dumps(pending_task['inputs'], default=str)}. Open questions:\n{format_questions(pending_task)}\n"
            "If the next message answers any of them, call plan_task with that template and put ONLY the values "
            "the user gave now in inputs, using the option values (the app merges them with what is known). If the "
            "user accepts the suggestions, pass the suggested values. If the user talks about something else, "
            "ignore this.")})
    if attachments:
        messages.append({"role": "system", "content": attachments_note(attachments)})
    messages.append({"role": "user", "content": user_text})
    specs = tools.openai_tool_specs()

    try:
        for round_no in range(settings.max_tool_rounds):
            msg = llm.chat(messages, specs)
            calls = msg.tool_calls or []
            if not calls:
                if round_no == 0 and route and not state.tools_used:
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
        final = llm.chat(messages + [{"role": "user", "content": "Answer now using the tool results above."}])
        return state.result(final.content or "(no answer)")
    except _NewTask:
        raise
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
    if state.prerequisites and not state.questions:
        return state.result(f"{head}\n\n{prereqs.format_report(state.prerequisites)}", llm_ok=False)
    if state.last_result:
        name, data = state.last_result
    elif route:
        state.used_fallback = True
        text = state.execute(*route)
        if state.prerequisites and not state.questions:
            return state.result(f"{head}\n\n{prereqs.format_report(state.prerequisites)}", llm_ok=False)
        if text.startswith(("ERROR", "SCRIPT", "QUESTIONS")):
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
