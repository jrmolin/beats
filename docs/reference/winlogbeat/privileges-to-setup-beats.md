---
navigation_title: "Create a _setup_ user"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/winlogbeat/current/privileges-to-setup-beats.html
applies_to:
  stack: ga
---

# Grant privileges and roles needed for setup [privileges-to-setup-beats]


::::{important}
Setting up Winlogbeat is an admin-level task that requires extra privileges. As a best practice, grant the setup role to administrators only, and use a more restrictive role for event publishing.
::::


Administrators who set up Winlogbeat typically need to load mappings, dashboards, and other objects used to index data into {{es}} and visualize it in {{kib}}.

To grant users the required privileges:

1. Create a **setup role**, called something like `winlogbeat_setup`, that has the following privileges:

    | Type | Privilege | Purpose |
    | --- | --- | --- |
    | Cluster | `monitor` | Retrieve cluster details (e.g. version) |
    | Cluster | `manage_ilm` | Set up and manage index lifecycle management (ILM) policy |
    | Index | `manage` on `winlogbeat-*` indices | Load data stream |

    Omit any privileges that aren’t relevant in your environment.

    ::::{note}
    These instructions assume that you are using the default name for Winlogbeat indices. If `winlogbeat-*` is not listed, or you are using a custom name, enter it manually and modify the privileges to match your index naming pattern.
    ::::

2. Assign the **setup role**, along with the following built-in roles, to users who need to set up Winlogbeat:

    | Role | Purpose |
    | --- | --- |
    | `kibana_admin` | Load dependencies, such as example dashboards, if available, into {{kib}} |
    | `ingest_admin` | Set up index templates and, if available, ingest pipelines |

    Omit any roles that aren’t relevant in your environment.


