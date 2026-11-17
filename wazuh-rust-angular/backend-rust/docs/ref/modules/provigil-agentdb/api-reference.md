# provigil-agentdb Query API & Socket Reference

Communication with `provigil-agentdb` occurs over the local Unix domain stream socket located at `queue/db/wdb`.

## Protocol Format

- Commands are sent as newline-terminated UTF-8 text strings:
  `agent <agent_id> <subcommand> [arguments]`
  or
  `global <subcommand> [arguments]`
  or
  `task <subcommand> [arguments]`
- Responses begin with a status indicator (`ok <payload>`, `err <message>`, or raw byte streams).

## Common Command Categories

### 1. Global Commands
- `global get-all-agents [status]`: Returns JSON list of all registered agents.
- `global get-agent-info <id>`: Returns metadata, IP, registration time, and OS version of the agent.
- `global get-labels <id>`: Returns JSON-encoded key-value labels assigned to agent `<id>`.
- `global get-agents-by-node-status <node> <status> <last_id> <limit>`: Paged query for node active agents.

### 2. Task Commands
- `task upgrade <agent_id> <task_id>`: Registers a new upgrade task.
- `task update_status <task_id> <status> [error_msg]`: Updates task status.
- `task get_tasks [agent_id]`: Lists tasks and execution states.

### 3. Agent Inventory & FIM Commands
- `agent <id> sql <query>`: Executes read queries directly against `queue/db/<id>.db`.
- `agent <id> syscollector os`: Returns stored operating system record.
- `agent <id> syscollector packages`: Returns package inventory for vulnerability scanning.
- `agent <id> fim find <file_path>`: Returns stored FIM hash and attribute checksums.
- `agent <id> sca get`: Returns compliance assessment scores and check statuses.
