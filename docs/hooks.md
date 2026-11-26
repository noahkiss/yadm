# Agent harness hooks

`yadm hook <event>` lets a coding-agent harness commit dotfile edits as they happen, tell the agent at once about a decision its edits caused, and keep it from ending a session with that decision open. `docs/design.md` section 9.7 states the behaviour. This document states the contract a harness, or glue between a harness and yadm, codes against.

## Events

| Event | Run it | Effect |
|---|---|---|
| `post-edit` | After a tool that writes or edits a file | Records the path for the session. Commits it locally if it is managed or in an owned root and no live lease names it; the next timer tick pushes it. Hooks never touch the network. Blocks on a decision on this path, on every edit, and on each untold decision on the session's other paths, once. When another process holds the sync lock, the path stays recorded for `stop` and the timer, and a decision already open on it still blocks. |
| `post-tool` | After every tool call | Blocks once on each untold decision on the session's recorded paths. Never commits. It reads the session record and local state and takes no lock, so it is cheap enough for every tool call. It reads the source only to build the packet of an untold decision. |
| `stop` | When the agent or a subagent ends its turn | Commits the session's recorded paths locally, except leased ones. Blocks while a decision this session caused is open, including a conflict the timer met while pushing them. On a leased path it blocks only for a conflict or a secrecy hold. When another process holds the sync lock for more than 3 s, it returns and the timer commits the paths. No process holds the sync lock while it waits on the network. |
| `session-start` | When a session starts or resumes | Quick sync, then a summary of at most 10 lines; it names each live lease with its holder, paths and expiry. The sync skips its network steps when another process holds the network lock. A schedule the service manager stopped running is reinstalled, at most once an hour, and the summary says so first. Then at most 10 lines of plugin news (design section 12.6): each allowed plugin's news query runs with a 3 s timeout and adds at most 5 lines; a slow or failing plugin adds one line and never fails the hook. |

## Input

One JSON object on stdin. The fields are those of the Claude Code hook input; other harnesses map their payload onto them. Unknown fields are ignored. Every field is optional.

| Field | Used by | Meaning |
|---|---|---|
| `hook_event_name` | `stop` | `SubagentStop` limits the stop check to `agent_id`'s own edits |
| `session_id` | all | Groups edits and told decisions; becomes the `Yadm-Session` trailer |
| `cwd` | all | Resolves a relative path; `session-start` lists holds under it first |
| `tool_name` | `post-edit` | Becomes the `Yadm-Tool` trailer |
| `tool_input.file_path`, `tool_input.notebook_path`, `tool_input.path` | `post-edit` | The edited file |
| `agent_id` | `post-edit`, `post-tool`, `stop` | The subagent that made the edit; `post-tool` in a subagent reports only its own paths |
| `action` | `post-edit` | Normalized tool kind: `shell`, `file_read`, `file_write`, `file_edit`, `web_fetch`, `web_search`, `mcp_call`, `agent_spawn`. Only empty, `file_write` and `file_edit` name a path. |
| `mcp_server` | none | With `action` = `mcp_call`, the MCP server that owns the tool. An adapter fills it, for example from a tool name such as `mcp__<server>__<tool>`. Other hook consumers may match on it; yadm ignores it. |
| `harness` | all | Opaque. Echoed in the verdict. yadm never branches on it. |
| `intent` | `post-edit` | A short reason for the edit, used as the commit subject |

A path outside `$HOME`, inside yadm's own directories, or neither managed nor in an owned root is ignored. A shell command names no path; the scheduled scan captures what it changed.

## Untold decisions

`post-edit` commits through the gate within the call, so a refusal there blocks the same edit. A decision can also arise after the hook returned: the timer captures a path `post-edit` left to it while a sync held the lock and the gate refuses it, or a sync meets an incoming change on a file the session edited. That decision is untold. The next `post-edit` or `post-tool` of the session blocks once on it, with its packet, and records it as told. A long or unattended turn therefore hears of it at its next tool call, not at its stop. `stop` still blocks on every open decision, told or not. Design section 9.7 states the rules.

## Output

| Exit | Decision | stdout | stderr |
|---|---|---|---|
| 0 | `allow`, nothing to say | empty | empty |
| 0 | `allow` with context | the verdict | empty |
| 2 | `block` | the verdict | the reason as text, with every packet and command |
| 1 | the hook failed | empty | the error |

Exit 1 never blocks: a broken yadm must not stop an agent. A machine that is not set up exits 0.

The verdict is one JSON object:

```json
{
  "schema": 1,
  "event": "stop",
  "decision": "block",
  "reason": "yadm: 1 decision(s) from this session are open; ...",
  "context": "",
  "updated_input": null,
  "harness": "<as given>",
  "packets": [
    {
      "id": "<hold id>",
      "kind": "new_file",
      "target": ".config/tool/new.conf",
      "scope": "shared",
      "what": "new file .config/tool/new.conf in an owned root",
      "diff": { "added": 3, "removed": 0 },
      "reaches": { "when": "", "machines": ["host-a", "host-b"], "types": ["work"] },
      "neighbours": [ { "target": ".config/tool/config", "when": "type:work" } ],
      "suggested_types": ["work"],
      "proposed": "commit it if every machine the root reaches should get it; ...",
      "options": [
        { "label": "share it", "consequence": "commits and pushes .config/tool/new.conf to host-a, host-b", "command": "yadm commit .config/tool/new.conf" },
        { "label": "decide later", "consequence": "the file stays held and uncommitted; ...", "command": "yadm defer <hold id> --reason \"<why it waits>\"" }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `decision` | `allow`, `block` or `ask`. yadm emits `allow` and `block` today. |
| `reason` | Why the decision blocks; the text an agent reads. |
| `context` | Text for the agent's context when nothing blocks (the `session-start` summary). |
| `updated_input` | A rewritten tool input. Optional; yadm sets none today. |
| `packets` | One per open decision. |

Packet `kind` is `new_file` or a hold reason: `protected`, `rendered_edit`, `check_failed`, `seal_guard`, `conflict`, `root_untrusted`, and the others in design section 14.1. `diff` counts lines only. No field ever carries the content of an enclave file. A `rendered_edit` packet on a shared template also carries `source` and `patch`.

With `--format text`, stdout carries the context as plain text instead of the verdict, and nothing on a block; a block still exits 2 with the reason on stderr.

`yadm defer <hold id> --reason <why> [--for <duration>]` settles a packet for a short wait, 6h by default and at most 48h: the hold stays, `yadm review list` shows it under `deferred` with its `until`, and `stop` no longer blocks on it. Its output carries a `note` that the agent stays responsible for the decision. When the defer expires unsettled, `stop` and `session-start` raise the decision again and `yadm check` warns; the timer still never commits it. The file stays uncommitted, through edits and timer scans, until the decision is settled: `yadm commit <path>` names it, `yadm retag` tracks it, `yadm hold ignore` ignores it, or the file is removed. A new file in an owned root that nobody decides on or defers is shared by the timer after its quiet period.

An agent that edits dotfiles over several tool calls and commits them with its own message takes a lease first: `yadm lease take <path...> --holder <name> --ttl <duration>`. While the lease lives, `post-edit` and `stop` in every session leave those paths alone: no commit, no decision, no block. A conflict or secrecy hold on a leased path still blocks. `stop` says `leased by <holder> until HH:MM` in its `context`. The agent commits with `yadm commit -m <subject> <path...>` and releases with `yadm lease release <name>`. A repeat `take` by the same holder adds paths and refreshes the TTL of all of them; `yadm lease release <name> <path...>` drops only those paths. A path still pending after the lease ends commits as usual. Design section 9.7 states the rules.

## Example: Claude Code

Claude Code blocks a stop on exit 2 and shows a `PostToolUse` hook's stderr to the model on exit 2. It adds a `SessionStart` hook's plain-text stdout to the context, and it validates a JSON object on stdout against its own schema. So every event uses `--format text`: stdout is plain text or empty, and a block reaches the model through stderr. No glue is needed. In a `settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [{ "type": "command", "command": "yadm hook post-edit --format text" }]
      },
      {
        "hooks": [{ "type": "command", "command": "yadm hook post-tool --format text" }]
      }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "yadm hook stop --format text" }] }
    ],
    "SubagentStop": [
      { "hooks": [{ "type": "command", "command": "yadm hook stop --format text" }] }
    ],
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "yadm hook session-start --format text" }] }
    ]
  }
}
```

The `post-tool` entry has no matcher, so it runs after every tool, edits included. On an edit it runs beside `post-edit`; the told record keeps the two from repeating a decision, except when both read it before either records it.

If `yadm` is not on the hook's `PATH`, use its absolute path, for example `<prefix>/bin/yadm`.

Claude Code ends a turn anyway after a fixed number of consecutive stop blocks. An agent that cannot settle a decision runs the `yadm defer` command from the packet.

## Other harnesses

Map the harness's payload onto the input fields above, and its verdict handling onto the exit codes. A harness that reads only exit codes and stderr needs no glue for `post-edit`, `post-tool` and `stop`. A harness that takes structured output reads `decision`, `reason` and `context` from the verdict.

A harness whose edit tool takes a patch rather than a path calls `post-edit` once per file the patch names. Glue that appends a block's stderr to the tool result reaches the model in the same way as Claude Code's exit 2. `post-tool` needs the same `session_id` that `post-edit` got; without a `post-edit` wiring the session records no paths, and `post-tool` and `stop` have nothing to report.
