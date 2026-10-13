"""Small helpers shared by the infrastructure recipes (compute, network, containers, storage)."""
import re

from core import lookups
from core.templates import FieldSpec, _choice, _int, _yes_no

YES_NO = [{"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}]
SETTINGS = [{"value": "default", "label": "Recommended defaults (fewer questions)"},
            {"value": "custom", "label": "Custom: show every option"}]


def ids(v) -> list[str]:
    """A list, or a comma/semicolon/space separated string -> list of non-empty strings."""
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x for x in re.split(r"[,;\s]+", str(v or "").strip()) if x]


def pick(options, what: str):
    """Validator: the value must be one of options(env, inputs)."""
    def check(env, inputs, v):
        return _choice(options(env, inputs), v, what)
    return check


def pick_many(options, what: str, min_n: int = 1, max_n: int = 0):
    def check(env, inputs, v):
        allowed = {o["value"] for o in options(env, inputs)}
        chosen = ids(v)
        bad = [x for x in chosen if x not in allowed]
        if bad:
            raise ValueError(f"not available {what}: {', '.join(bad)}")
        if len(chosen) < min_n:
            raise ValueError(f"pick at least {min_n} {what}")
        if max_n and len(chosen) > max_n:
            raise ValueError(f"pick at most {max_n} {what}")
        return list(dict.fromkeys(chosen))
    return check


def static(options: list[dict]):
    return lambda env, inputs: options


def opts(*pairs) -> list[dict]:
    return [{"value": v, "label": label} for v, label in pairs]


def yes_no(key: str, question: str, default: str = "no", why: str = "", relevant=None, must_ask=False) -> FieldSpec:
    return FieldSpec(key, question, "choice", default=default, options=static(YES_NO),
                     validate=lambda e, i, v: _yes_no(v), relevant=relevant, why=why, must_ask=must_ask)


def number(key: str, question: str, default, lo: int, hi: int, why: str = "", relevant=None,
           must_ask=False) -> FieldSpec:
    return FieldSpec(key, question, "number", default=default, validate=lambda e, i, v: _int(v, lo, hi, key.replace("_", " ")),
                     relevant=relevant, why=why, must_ask=must_ask)


def choice(key: str, question: str, options: list[dict], default=None, why: str = "", relevant=None,
           must_ask=False) -> FieldSpec:
    return FieldSpec(key, question, "choice", default=default, options=static(options),
                     validate=pick(static(options), key.replace("_", " ")), relevant=relevant, why=why,
                     must_ask=must_ask)


def custom(i: dict) -> bool:
    return i.get("settings") == "custom"


def settings_field(why: str = "Custom shows the advanced options; defaults are safe and cheap.") -> FieldSpec:
    return FieldSpec("settings", "Use recommended defaults or customise every option?", "choice", default="default",
                     options=static(SETTINGS), validate=pick(static(SETTINGS), "settings"), why=why)


def action_is(*names):
    return lambda i: i.get("action") in names


def both(*preds):
    return lambda i: all(p(i) for p in preds)


def yes(i: dict, key: str) -> bool:
    return str(i.get(key, "no")).lower() == "yes"


def vpc_options(env, inputs):
    return [{"value": v["id"], "label": f"{v['id']} · {v['cidr']} · {v['name'] or ('default VPC' if v['default'] else '')}"}
            for v in lookups.vpcs(env)]


def subnet_options(public_only: bool = False, vpc_key: str | None = None):
    def options(env, inputs):
        vpc = inputs.get(vpc_key) if vpc_key else None
        return [{"value": s["id"], "label": f"{s['id']} · {s['az']} · {s['cidr']} · "
                                            f"{'public' if s['public'] else 'private'} · {s['vpc_name'] or s['vpc']}"
                                            f"{' · ' + s['name'] if s['name'] else ''}"}
                for s in env.subnets() if (s["public"] or not public_only) and (not vpc or s["vpc"] == vpc)]
    return options


def validate_subnets(min_azs: int = 1, public_only: bool = False, vpc_key: str | None = None):
    def check(env, inputs, v):
        chosen = ids(v)
        subs = {s["id"]: s for s in env.subnets()}
        bad = [x for x in chosen if x not in subs or (public_only and not subs[x]["public"])]
        if bad:
            kind = "public subnet" if public_only else "subnet"
            raise ValueError(f"not a {kind} in this region: {', '.join(bad)}")
        if not chosen:
            raise ValueError("pick at least one subnet")
        if len({subs[x]["vpc"] for x in chosen}) > 1:
            raise ValueError("all subnets must be in the same VPC")
        if vpc_key and inputs.get(vpc_key) and subs[chosen[0]]["vpc"] != inputs[vpc_key]:
            raise ValueError(f"the subnets must be in {inputs[vpc_key]}")
        if len({subs[x]["az"] for x in chosen}) < min_azs:
            raise ValueError(f"pick subnets in at least {min_azs} different availability zones")
        return chosen
    return check


def default_subnets(public_only: bool = False, n: int = 2):
    def default(env, inputs):
        subs = [s for s in env.subnets() if s["public"] or not public_only]
        if not subs:
            return []
        vpc = subs[0]["vpc"]
        out, azs = [], set()
        for s in subs:
            if s["vpc"] == vpc and s["az"] not in azs:
                out.append(s["id"])
                azs.add(s["az"])
        return out[:n]
    return default


def sg_options(vpc_of, new_label: str | None = None):
    """Security groups in the VPC returned by vpc_of(env, inputs); optional 'new' entry first."""
    def options(env, inputs):
        vpc = vpc_of(env, inputs)
        out = [{"value": "new", "label": new_label}] if new_label else []
        if vpc:
            out += [{"value": g["id"], "label": f"{g['id']} · {g['name']} · {g['desc'][:40]}"}
                    for g in env.security_groups(vpc)]
        return out
    return options


def cidr(v, what: str = "IP range", min_prefix: int = 0) -> str:
    import ipaddress
    try:
        net = ipaddress.ip_network(str(v).strip(), strict=False)
    except ValueError:
        raise ValueError(f"{what}: enter an address range like 10.0.0.0/16 or 203.0.113.5/32") from None
    if net.prefixlen < min_prefix:
        raise ValueError(f"{what} is too wide (/{net.prefixlen}); use /{min_prefix} or smaller")
    return str(net)


def kv_pairs(text: str, what: str = "KEY=VALUE pairs") -> dict:
    """'A=1; B=two' -> {'A': '1', 'B': 'two'}."""
    out = {}
    for part in re.split(r"[;\n]+", str(text or "")):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"'{part}' is not KEY=VALUE ({what})")
        k, v = part.split("=", 1)
        k = k.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", k):
            raise ValueError(f"'{k}' is not a valid name ({what})")
        out[k] = v.strip()
    return out


SECRET_NAME_RE = re.compile(r"(?i)(secret|password|passwd|token|api_?key|private_?key|access_?key)")
SECRET_VALUE_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----")


def no_secrets(pairs: dict, what: str) -> dict:
    for k, v in pairs.items():
        if SECRET_NAME_RE.search(k) or SECRET_VALUE_RE.search(v):
            raise ValueError(f"{k} looks like a secret. Scripts are stored and shown, so put secrets in Secrets "
                             f"Manager or SSM Parameter Store yourself and pass only the name ({what})")
    return pairs


def account_ids(v) -> list[str]:
    out = ids(v)
    bad = [x for x in out if not re.fullmatch(r"\d{12}", x)]
    if bad:
        raise ValueError(f"AWS account IDs have 12 digits: {', '.join(bad)}")
    return out


def region_options(env, inputs):
    return [{"value": r, "label": r} for r in lookups.regions(env)]


def utc_hhmm(text: str, tz: str | None = None) -> str:
    """'10:00' in the app timezone -> 'HH:MM' in UTC (code does the timezone math)."""
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo

    from core.config import settings
    from core.schedules import parse_hhmm
    t = parse_hhmm(str(text))
    local = datetime.now(ZoneInfo(tz or settings.app_timezone)).replace(hour=t.hour, minute=t.minute, second=0,
                                                                          microsecond=0)
    utc = local.astimezone(timezone.utc)
    return f"{utc.hour:02d}:{utc.minute:02d}"


def extra_params_field(main_call, reserved: set, relevant=None, key: str = "extra_params") -> FieldSpec:
    """Optional JSON with ANY other parameter of the recipe's main create call, checked against the botocore
    model. main_call(inputs) -> (service, operation)."""
    def check(env, inputs, v):
        import difflib
        import json
        from botocore.validate import ParamValidator
        from core.scripts import ScriptError, _model_client, check_write_allowed
        if isinstance(v, dict):
            obj = v
        else:
            s = str(v or "").strip()
            if not s or s == "{}":
                return ""
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                raise ValueError('must be a JSON object of AWS parameter names, e.g. {"Description": "web"}') from None
        if not isinstance(obj, dict):
            raise ValueError("must be a JSON object of AWS parameter names and values")
        if not obj:
            return ""
        service, op = main_call(inputs)
        client = _model_client(service)
        shape = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op]).input_shape
        for k in obj:
            if k in reserved:
                raise ValueError(f"'{k}' is set by the recipe itself (use the matching question instead)")
            if k not in shape.members:
                near = difflib.get_close_matches(k, list(shape.members), n=3)
                raise ValueError(f"'{k}' is not a parameter of {service}.{op}"
                                 + (f"; did you mean {', '.join(near)}?" if near else ""))
        report = ParamValidator().validate(obj, shape)
        if report.has_errors():
            lines = [ln for ln in report.generate_report().splitlines()[1:] if "Missing required parameter" not in ln]
            if lines:
                raise ValueError("; ".join(ln.strip() for ln in lines)[:300])
        try:
            check_write_allowed(service, op, obj)
        except ScriptError as e:
            raise ValueError(str(e)) from None
        return json.dumps(obj, sort_keys=True)

    return FieldSpec(key, "Any other AWS parameters for the main create call? (optional JSON, AWS API names)",
                     "text", default="", allow_empty=True, validate=check, relevant=relevant or custom,
                     why="For any setting without its own question. Checked against the AWS API model before saving.")


def merge_extra(params: dict, v: dict, key: str = "extra_params") -> dict:
    import json
    if v.get(key):
        params.update(json.loads(v[key]))
    return params
