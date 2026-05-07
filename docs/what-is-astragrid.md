# What Is AstraGrid

This manual explains AstraGrid in plain language. It is written like a direct conversation, not like
an engineering spec.

## Short Answer

AstraGrid is a local mission-control system.

Think of it like a serious field notebook plus command center:

- It records what happened.
- It records who did it.
- It records why the decision was made.
- It keeps evidence with the decision.
- It can work offline.
- It can prove later that the record was not silently changed.

It is not a country-specific flood app. It is not live government data. It is not a weather service.
The current `flood-watch-preview` mission is only a realistic sample mission used to show how the
system behaves.

## Why It Exists

In a crisis, normal chat and spreadsheets become messy fast.

Example: there is flooding, a bridge is blocked, a field team is dispatched, and someone needs to
approve a follow-up action. After one hour, people ask:

- Who reported the incident?
- Who approved the action?
- Which evidence was used?
- Did another laptop receive the same mission record?
- Was any record edited later?
- Can we recover the workspace if the laptop dies?

AstraGrid is built to answer those questions from local files, even when internet is weak or not
available.

## The Flood Example

`flood-watch-preview` means:

- Mission name: flood watch preview.
- Country: no country. It is sample data.
- Incident: river-east is above a danger level.
- Dispatch: a team was sent to river-east.
- Observation: bridge-south has a field note.
- Approval: one follow-up decision is waiting.
- Peer sync: two other devices/peers need to receive or compare data.

You can rename the mission to anything:

- `karachi-rain-response`
- `factory-fire-drill`
- `border-medical-logistics`
- `pipeline-inspection`
- `warehouse-security-shift`

The system does not care about the country. It cares about verified mission records.

## What The Operator Console Is

The Operator Console is the browser view.

Its job is not to be a social feed. Its job is to answer:

1. Is the mission record healthy?
2. What is happening right now?
3. What needs operator attention?
4. Which decisions are waiting?
5. Which peers/devices need sync?
6. Is there evidence behind the actions?

The console is read-only right now. Real changes still go through the CLI so every action is signed,
checked, and recorded.

## What The Top Numbers Mean

### Verified Records

These are the mission log entries that passed integrity checks.

In normal words: "How many trusted records are in this mission?"

Example records:

- Mission opened.
- Incident declared.
- Team dispatched.
- Observation recorded.

### Active Incidents

These are problems that are still open.

If this says `1`, it means one incident still needs attention.

### Decisions Waiting

These are approval items.

If this says `1`, it means someone has prepared an action, but it still needs review or approval
before execution.

### Sync Jobs Due

These are peer/device sync tasks waiting to run.

If this says `2`, it means AstraGrid has two peer sync jobs queued. It does not mean the world is
broken. It means two configured peers have pending sync work.

### Evidence Packs

These are evidence bundles attached to recommendations or decisions.

Example: a sensor reading, field note, or inspection record used to justify an action.

## What "Mission State Verified" Means

It means AstraGrid checked the mission ledger and the hash chain is valid.

In normal words: "The mission record still matches its own proof trail."

This does not mean the real-world incident is solved. It means the local mission record is internally
trustworthy.

## What "Proof" Means

Proof does not mean court proof. It means cryptographic integrity proof.

AstraGrid stores each record with a hash. A hash is like a fingerprint for data.

If someone edits an old record, the fingerprint changes. Then verification fails.

The UI shows a short proof like:

```text
d9d23beda6...3501d3
```

That is a shortened hash. It helps operators know which verified record they are looking at without
showing a huge technical string.

## What "Threats" Means In This Project

Threats here means project risks, not live enemy threats.

The threat model asks:

- What if someone edits the mission file?
- What if a fake operator tries to append a command?
- What if a laptop is stolen?
- What if a peer sends bad data?
- What if an AI runner invents evidence?
- What if a release package is tampered with?

So "threat model" is security planning for the software. It is not saying there is an actual attack
or flood happening.

## What The Tabs Mean

### Overview

This is the main screen.

Look here first. It should answer:

- Is the mission record healthy?
- How many incidents are active?
- Are there decisions waiting?
- Are peers waiting for sync?
- What happened most recently?

### Mission Events

This is the verified mission history.

It is like an audit notebook:

- Mission opened.
- Incident declared.
- Team dispatched.
- Observation recorded.

Every row has an order and a short proof.

### Approvals

This shows decisions that need review.

Example: "Close incident river-east" is prepared, but not executed until approved.

### Audit Timeline

This is a combined story of important actions from ledger, approvals, peer sync, and evidence.

Use it when you want to understand the sequence of operational activity.

### Peer Sync

This shows sync work for other devices or sites.

Example:

- north-gateway needs a sync.
- field-tablet-cache needs a sync.

This is useful when multiple laptops or field nodes are part of the same mission.

## The Basic Workflow

1. Create a workspace.
2. Create or load an operator key.
3. Open a mission.
4. Add mission events.
5. Attach evidence.
6. Draft a decision.
7. Approve or reject the decision.
8. Sync with peers if needed.
9. Export reports or backup the workspace.

## Why CLI Still Matters

The UI is for reading and understanding.

The CLI is for real mutation:

- append signed event
- approve decision
- rotate key
- backup workspace
- restore workspace
- verify ledger
- sync peers

This is intentional. It keeps dangerous writes explicit and auditable.

## In One Example

Suppose a flood team is working.

An operator records:

```text
Incident declared: river-east water level is high.
```

Then another action is recorded:

```text
Team dispatched: alpha team sent to river-east.
```

Then evidence is attached:

```text
Sensor reading: water=5.2m.
```

Then someone drafts:

```text
Close incident after field verification.
```

That decision waits in Approvals until someone approves it.

The console shows this as a mission brief instead of forcing the operator to read raw JSON files.

## What AstraGrid Is Not Yet

It is not yet a public SaaS product.

It does not yet include:

- Real TPM/YubiKey hardware-key workflow.
- Signed MSI or winget installer.
- Remote update channel.
- Hosted remote certificate authority.
- Full native desktop app.
- Real field deployment drills across multiple physical sites.

The local kernel, CLI, ledger, evidence, approval, backup, restore, sync queue, and browser console
exist and are tested.

## Simple Mental Model

If WaseemBot is an AI operating brain, AstraGrid is a field mission black box.

It remembers what happened, who did it, why it happened, and whether the record still proves itself.

