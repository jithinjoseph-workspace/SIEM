# provigil-modulesd Configuration

Module configuration is declared in `etc/ossec.conf` under `<wodle>` or `<modules>` blocks.

## Example Configuration

```xml
<ossec_config>
  <!-- Task Manager Configuration -->
  <task_manager>
    <enabled>yes</enabled>
    <task_timeout>300</task_timeout>
    <cleanup_interval>86400</cleanup_interval>
  </task_manager>

  <!-- Vulnerability Detector Orchestration -->
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
  </wodle>
</ossec_config>
```

## Options Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `task_manager.enabled` | boolean | `yes` | Enables fleet task management and agent upgrade tracking. |
| `task_manager.task_timeout` | integer | `300` | Seconds before an in-progress agent task is marked as timed out. |
| `task_manager.cleanup_interval` | integer | `86400` | Pruning interval for historical completed task records. |
| `vulnerability-detector.interval` | duration | `5m` | Frequency of background scan checks against updated inventories. |
