"""The only implemented risk rule: direct privileged executable invocation."""
from pathlib import PurePosixPath, PureWindowsPath

from ..schemas import ToolCall

RULE_ID = "R002"
RULE_VERSION = "1.0"


def executable(call: ToolCall) -> str:
    args = call.arguments
    path = PureWindowsPath if args.get("path_flavor", "posix") == "windows" else PurePosixPath
    name = path(args["argv"][0]).name
    return name.lower() if path is PureWindowsPath else name


def unknown_reason(call: ToolCall) -> str | None:
    if call.tool not in {"process.exec", "filesystem.write", "http.request"}:
        return "Unknown tool; analysis coverage is unavailable."
    if call.tool == "process.exec":
        name = executable(call)
        if call.arguments["shell"] or name in {"sh", "bash", "dash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "env", "python", "python3", "node"}:
            return "Shell, interpreter, or wrapper content is opaque to this detector."
    return None


def detect(call: ToolCall) -> list[dict]:
    if call.tool != "process.exec" or call.arguments["shell"]:
        return []
    if executable(call) not in {"sudo", "su", "doas"}:
        return []
    return [{
        "rule_id": RULE_ID,
        "rule_version": RULE_VERSION,
        "severity": "high",
        "event_ids": [call.event_id],
        "field": "arguments.argv[0]",
        "evidence": call.arguments["argv"][0][:256],
        "message": "Direct privileged executable invocation; privilege gain is not verified.",
    }]
