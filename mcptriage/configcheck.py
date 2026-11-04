"""Static checks on MCP client config files.

Covers the shape shared by Claude Desktop / Claude Code ("mcpServers") and
VS Code ("servers"). Deliberately light: deep client-specific quirks (Windows
npx shims, GUI PATH differences) are the territory of dedicated client-side
checkers. mcptriage keeps config checks to what generalizes, and spends its
depth on transcript diagnosis.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from .rules import Finding, HIGH, LOW, MEDIUM

_ENV_REF = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


class _DuplicateConfigKey(ValueError):
    """A repeated JSON key makes the config ambiguous; never retain its text."""


def _unique_config_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateConfigKey
        obj[key] = value
    return obj


def _servers_from(obj: Any) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not isinstance(obj, dict):
        return None, None
    for key in ("mcpServers", "servers"):
        servers = obj.get(key)
        if isinstance(servers, dict):
            return key, servers
    return None, None


def check_config_text(text: str, path: str = "<config>") -> List[Finding]:
    findings: List[Finding] = []
    try:
        obj = json.loads(text, object_pairs_hook=_unique_config_object)
    except json.JSONDecodeError as exc:
        return [Finding(
            "CFG_JSON_ERROR", HIGH,
            "config is not valid JSON: %s" % exc.msg,
            "%s:%d:%d" % (path, exc.lineno, exc.colno),
            "The client silently ignores a config it cannot parse; the server simply "
            "never appears.",
            "Fix the JSON syntax at the reported position (common causes: trailing "
            "commas, unquoted backslashes in Windows paths).",
        )]
    except _DuplicateConfigKey:
        return [Finding(
            "CFG_JSON_DUPLICATE_KEY", HIGH,
            "config contains repeated JSON object keys",
            path,
            "Different parsers can select different values for a repeated key. "
            "Checking only one value could hide a server or launch setting, "
            "so no server entries were checked.",
            "Remove repeated keys, retaining the intended settings explicitly, "
            "then run the check again. Repeated names and values are not echoed.",
        )]
    except (ValueError, RecursionError):
        return [Finding(
            "CFG_JSON_LIMIT", HIGH,
            "config JSON exceeds the runtime decoder's supported limits",
            path,
            "The Python runtime could not decode this config because of an integer "
            "conversion or nesting limit. This is not proof that its JSON syntax "
            "is invalid, and no server entries could be checked.",
            "Reduce extreme integer literals or nesting, check that this is the "
            "intended client config, and run the check again. No values are coerced.",
        )]
    key, servers = _servers_from(obj)
    if servers is None:
        return [Finding(
            "CFG_NO_SERVERS", HIGH,
            "no 'mcpServers' (or 'servers') object found",
            path,
            "Without a servers map the client has nothing to launch.",
            "Add an 'mcpServers' object naming each server and its command or url.",
        )]
    if not servers:
        findings.append(Finding(
            "CFG_NO_SERVERS", HIGH,
            "'%s' is present but empty" % key,
            path,
            "An empty servers map means no servers are configured.",
            "Add at least one server entry.",
        ))
        return findings
    base_dir = os.path.dirname(os.path.abspath(path)) if path != "<config>" else os.getcwd()
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            findings.append(Finding(
                "CFG_SHAPE", HIGH,
                "server '%s' is not an object" % name,
                "%s: '%s'" % (path, name),
                "Each server entry must be an object with a command or a url.",
                "Give the entry a 'command' (stdio) or 'url' (remote) plus its fields.",
            ))
            continue
        findings.extend(_check_server(name, spec, path, base_dir))
    return findings


def _check_server(name: str, spec: Dict[str, Any], path: str, base_dir: str) -> List[Finding]:
    findings: List[Finding] = []
    # Validate field shapes independently of truthiness. Never echo malformed
    # values, which may contain credentials, or use them as endpoint evidence.
    bad_fields = []
    for field in ("command", "url", "envFile", "type"):
        if field in spec and not isinstance(spec[field], str):
            bad_fields.append(field)
    if "args" in spec and (not isinstance(spec["args"], list)
                           or not all(isinstance(arg, str) for arg in spec["args"])):
        bad_fields.append("args")
    if "env" in spec and (not isinstance(spec["env"], dict)
                          or not all(isinstance(value, str) for value in spec["env"].values())):
        bad_fields.append("env")
    for field in bad_fields:
        findings.append(Finding(
            "CFG_SHAPE", HIGH if field in ("command", "url") else MEDIUM,
            "server '%s' %s has an unusable field type" % (name, field),
            "%s: '%s' field '%s'" % (path, name, field),
            "command, url, envFile and type must be strings; args must contain only "
            "strings; env must map variable names to string values. "
            "The malformed value is not used as launch or endpoint evidence.",
            "Check the client's config format and fix the field's JSON type "
            "without converting secret values into diagnostic text.",
        ))
    command = spec.get("command") if isinstance(spec.get("command"), str) else None
    url = spec.get("url") if isinstance(spec.get("url"), str) else None
    stype = spec.get("type") if isinstance(spec.get("type"), str) else None
    if command and url:
        findings.append(Finding(
            "CFG_SHAPE", MEDIUM,
            "server '%s' sets both 'command' and 'url'" % name,
            "%s: '%s'" % (path, name),
            "A server is either a local stdio command or a remote endpoint, not both; "
            "clients pick one and the other silently does nothing.",
            "Remove the field that does not apply.",
        ))
    if not command and not url:
        findings.append(Finding(
            "CFG_SHAPE", HIGH,
            "server '%s' has neither 'command' nor 'url'" % name,
            "%s: '%s'" % (path, name),
            "The client cannot launch or reach this server.",
            "Add 'command' with args for a local server, or 'url' for a remote one.",
        ))
    if stype and stype not in ("stdio", "sse", "http", "streamable-http"):
        findings.append(Finding(
            "CFG_SHAPE", LOW,
            "server '%s' has unrecognized type %r" % (name, stype),
            "%s: '%s'" % (path, name),
            "Clients ignore or misroute unknown transport types.",
            "Use 'stdio', 'sse', or 'http' (client spellings vary; check its docs).",
        ))
    if isinstance(command, str) and command:
        findings.extend(_check_command(name, command, path))
    env = spec.get("env")
    if isinstance(env, dict):
        for env_key, env_val in env.items():
            if isinstance(env_val, str):
                for ref in _ENV_REF.findall(env_val):
                    if ref not in os.environ:
                        findings.append(Finding(
                            "CFG_ENV_UNSET", MEDIUM,
                            "server '%s' env '%s' references ${env:%s}, which is not set"
                            % (name, env_key, ref),
                            "%s: '%s'" % (path, name),
                            "Clients interpolate ${env:VAR} from their own environment; "
                            "a GUI app launched from a desktop icon often has a smaller "
                            "environment than a terminal, so the variable resolves empty.",
                            "Set the variable for the client app's environment, or "
                            "inline the value (watch secrets) in the config.",
                        ))
    env_file = spec.get("envFile")
    if isinstance(env_file, str):
        candidate = env_file
        if not os.path.isabs(candidate):
            candidate = os.path.join(base_dir, candidate)
        if not os.path.exists(candidate):
            findings.append(Finding(
                "CFG_ENVFILE_MISSING", MEDIUM,
                "server '%s' envFile %r does not exist" % (name, env_file),
                "%s: '%s'" % (path, name),
                "A missing envFile leaves the server without credentials it expects; "
                "failures then appear inside the server, far from the cause.",
                "Create the file or fix the path (relative paths resolve against the "
                "config file's folder).",
            ))
    return findings


def _check_command(name: str, command: str, path: str) -> List[Finding]:
    if os.sep in command or "/" in command or "\\" in command:
        if not os.path.exists(command):
            return [Finding(
                "CFG_COMMAND_MISSING", HIGH,
                "server '%s' command path %r does not exist" % (name, command),
                "%s: '%s'" % (path, name),
                "The client cannot start a command whose path does not resolve.",
                "Fix the path or use a command available on PATH.",
            )]
        return []
    if shutil.which(command) is None:
        return [Finding(
            "CFG_COMMAND_MISSING", MEDIUM,
            "server '%s' command %r is not on this machine's PATH" % (name, command),
            "%s: '%s'" % (path, name),
            "The command is missing here. Note GUI clients use their own PATH, which "
            "may differ from this shell's.",
            "Install the command or use an absolute path; verify the client app's "
            "PATH, not just the terminal's.",
        )]
    return []


def check_config_file(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return check_config_text(fh.read(), path)
