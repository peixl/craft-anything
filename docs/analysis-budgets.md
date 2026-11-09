# Analysis coverage and workflow budgets

Analysis size and execution permission are separate choices. Deep mode exposes the registered analysis
tools; the following options let a long investigation continue without changing command, file, credential
or plugin permissions. Existing settings keep their meanings.

## Available controls

| Work | Control | What changes |
|---|---|---|
| Reading inside targets | `deep_mode = true`, or CLI `--deep` | Uses the available internal-analysis tools; fresh installations already use Deep |
| Discovering tool groups | `enable_toolset` with `all` | Lists every registered group; a known tool also enables its own group when called |
| Built-in AI steps | `unlimited_turns = true` in an existing `[[ai.backends]]` entry | Removes that API/local backend's per-message step cap; external agent CLIs own their loops |
| Build refinements | `build.unlimited_rounds = true`, CLI `rebuild --unlimited-rounds`, or `rebuild_start` with `unlimited_rounds: true` | Keeps refining until checks meet the goal, the run is cancelled, or another independent stop condition occurs |
| Website sample count | `build.unlimited_pages = true` | Removes the selected page-count budget for discovered same-origin routes |
| Website exploration depth | `build.max_page_depth` | Selects how many link levels to explore; default `2`, explicit `0` removes the depth budget |
| Pseudo-C export | `native_source_folder_write` with `engine: "auto"` and `unlimited: true` | Uses the available Deep decompiler with builtin fallback and removes the per-call function/time budget |

Add these keys to the existing `[build]` table to choose unlimited refinement and sampling budgets:

```toml
[build]
unlimited_rounds = true
unlimited_pages = true
max_page_depth = 0
```

The new flags default to false. A finite `max_pages` above 12 is now honoured rather than silently
clamped to 12. The new depth setting does not change the existing zero meanings: `max_pages = 0`
still means no additional pages, and `max_rounds = 0` still means an initial build without refinements.
Explicit unlimited selects a different budget; it does not rewrite those saved numbers.

An explicit finite CLI/tool round count overrides an inherited unlimited setting. An explicit unlimited
request wins over the numeric cap. Omitted numeric values keep the existing entry-point defaults
(the app's configured count; two refinements for CLI/tool calls).

The same controls are in Settings → Builds: select Unlimited beside rounds or pages, and set
Website depth to zero for no depth budget. Turning Unlimited off restores the saved finite number.
Opening the settings page does not clamp a previously saved large count.

`capture/routes-coverage.json` records successful captures separately from attempts, failures and
redirects. Finite page budgets count successful captures, so a failed page does not consume a
successful-page slot. Captured progress is saved before cancellation. The initial builder prompt
summarizes at most 32 routes and points to the complete retained list in `capture/routes.json`.

## Deep export and continuation

`native_source_folder_write` writes one file per discovered function and checkpoints its progress.
New output folders select `auto`: Deep when available, otherwise builtin, with each file's actual
engine and provenance recorded. A missing optional Ghidra installation does not block builtin work;
installing it remains an explicit action.

Existing version-1 exports resume with the builtin policy they started with. The selected policy is
saved separately from each file's engine; use a new output folder to change policy. Resume checks
the target identity and preserves unrelated files. A record whose output file is missing is not counted
as completed.

Without `unlimited`, the existing zero rules remain: `max_functions = 0` is invalid and
`max_seconds = 0` writes no functions. Positive function/time budgets can be raised without the
former arbitrary upper ceilings. The written-file preview stays bounded; full output is on disk.

The export covers the builtin analysis's discovered candidate functions. It now uses Deep for their
code, but it does not call Ghidra's unpaged whole-function catalogue. Discovery boundaries are reported
explicitly; “finished” means the discovered candidates were written, not proof that every possible
function in a program was found.

## Boundaries that remain

- Cancellation, process ownership/deadlines, atomic writes, target hashes and output-folder checks.
- Per-response and retained-data bounds, including parser recursion/allocation limits and bounded
  website traversal state. Sampling reports partial coverage when it reaches such a boundary.
- Same-origin route selection, including redirect checks; attempted routes are remembered so failed
  links and cycles do not create an endless retry loop.
- Existing failed-build and no-progress detection. Unlimited useful work is separate from repeatedly
  failing without progress.
- Explicit Clean room, command execution, outside-project file access, credential and plugin rules.

Current retained-data bounds are explicit: 256 captured routes and 256 queued routes, 4,096 visited
routes, 16,384 inspected links per page, 2,048 bytes per URL, 8 MiB per capture JSON, 4 MiB per route
manifest, 64 MiB per export checkpoint, and 65,536 check records / 16 MiB of serialized check history.
Reaching a resource bound reports it and preserves the last valid checkpoint; it does not silently
drop old results or call a partial analysis complete.

The rebuild reminder uses successful, attributable evidence for the current target and call. A tool
starting, an all-failed batch, an unrelated record or an adapter completion without a result id does
not establish that decompilation succeeded. Single and batch results both count when their evidence
is attributable; unsupported native targets do not receive an impossible native-decompilation reminder.

Encrypted archive decryption and a genuinely paged Deep function catalogue are missing capabilities,
not switches. They require their own implementations; neither is supplied by deleting a restriction.
