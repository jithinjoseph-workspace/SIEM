# provigil-modulesd API & IPC Reference

`provigil-modulesd` communicates through Unix domain sockets located in `queue/tasks/` and `queue/sockets/`.

## IPC Interfaces

### 1. Task Management Socket (`queue/tasks/task`)
- **Protocol**: Length-delimited JSON commands over Unix domain stream.
- **Commands**:
  - `upgrade`: Dispatches an agent binary upgrade package instruction.
    ```json
    { "command": "upgrade", "parameters": { "agents": [1, 2, 3], "version": "4.14.7", "force": false } }
    ```
  - `upgrade_custom`: Dispatches custom package upgrade URL with SHA-256 verification hash.
  - `get_status`: Queries current status of an ongoing task ID.
  - `cancel`: Cancels an active or pending task.

### 2. Message Bus / Router Socket (`queue/sockets/router`)
- Used by internal daemons to broadcast inventory events, alerts, and system state transitions across the manager.
