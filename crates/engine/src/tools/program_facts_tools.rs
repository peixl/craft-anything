//! Facts read from a program or model file without running it: imports, exports, a Windows
//! program's signature block, AI model headers. Also pairing the functions of two builds, and
//! writing pseudo-C to a folder across several runs. Nothing here executes the target.

use super::native_common::{CtxControl, disasm_err, native, page, params_json, select_document, spec};
use super::static_input::{self, builder, format_err};
use super::{Detail, detailed};
use crate::tool::{Ctx, Effects, Requires, ToolOutput, ToolSpec, Toolset, parse_params, schema_of};
use craft_anything_analysis::function_match::{self, BodyStatus, MatchMethod, MatchResult, MatchedPair};
use craft_anything_disasm::{Image, Limits, Program};
use craft_anything_evidence::{Authority, Confidence, Coverage, CoverageStatus, Environment, ErrorCode, Limitation, Location, ToolError};
use craft_anything_formats::authenticode::{self, CertTable, HashStatus, SignatureReport};
use craft_anything_formats::verify::Verified;
use craft_anything_formats::{Binary, Format, ai_model, elf, macho_deps, parse_binary, pe};
use craft_anything_platform::fs::write_atomic;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Largest program read whole (2 GiB).
const MAX_PROGRAM: u64 = 2 << 30;
/// Largest program analysed for a match, unless the call raises it.
const DEFAULT_MATCH_BYTES: u64 = 512 << 20;
/// Bytes of a model file read by default.
const DEFAULT_HEADER_BYTES: u64 = 256 << 20;
const MAX_HEADER_BYTES: u64 = 4 << 30;
const MIN_HEADER_BYTES: u64 = 1 << 10;

pub fn specs() -> Vec<ToolSpec> {
    let e = Effects::EVIDENCE | Effects::CARRIES_TARGET_CONTENT;
    vec![
        spec(
            "native_library_calls_list",
            "What a program imports",
            "The functions a program takes from other libraries, without analysing it. Windows programs: the import directory, the delay-load directory and bound imports, by name (with hint) or by ordinal, each saying which kind it is. ELF: the dynamic symbols with their needed version and library. Mach-O: bound symbols with how each library is linked. Libraries are summarised first, then rows are paged (offset/limit); contains keeps rows whose name or library holds that text, kind keeps one kind. Uses the active target unless path is given.",
            "See which outside libraries and functions a program uses.",
            Toolset::Formats,
            e,
            Requires::Nothing,
            schema_of::<ListParams>,
            native_library_calls_list,
        ),
        spec(
            "native_offered_symbols_list",
            "What a program exports",
            "The functions and data a program or library offers to others, without analysing it. Windows: the export directory with ordinals, names, ordinal-only entries and forwarders to other libraries. ELF: exported dynamic symbols with their versions. Mach-O: the export list. Paged (offset/limit); contains keeps rows whose name or forwarder holds that text. Uses the active target unless path is given.",
            "See what a library offers to the programs that use it.",
            Toolset::Formats,
            e,
            Requires::Nothing,
            schema_of::<ExportParams>,
            native_offered_symbols_list,
        ),
        spec(
            "native_publisher_show",
            "Who signed this Windows program",
            "Read a Windows program's Authenticode signature block: each certificate table entry, the signer's subject, issuer, serial and validity dates, every embedded certificate, and the digest algorithm. Checks what the file alone can show: its hash against the signed hash, the signature against the embedded signer certificate, and how the embedded certificates link. Doesn't check whether Windows trusts them, revocation, expiry against any date, or catalog signing, and lists timestamps and nested signatures without reading them. Uses the active target unless path is given.",
            "Find out who signed a Windows program, and whether the file still matches that signature.",
            Toolset::Formats,
            e,
            Requires::Nothing,
            schema_of::<SignerParams>,
            native_publisher_show,
        ),
        spec(
            "formats_ai_weights_show",
            "AI model file",
            "Read an AI model file's header: GGUF (versions 2 and 3) or safetensors. Architecture, name, quantization, approximate parameter count, metadata keys and values (long values shortened), and tensors with their types and shapes, paged (offset/limit). Reads at most max_header_bytes from the start of the file, so very large models are fine; tensor data is never read. Uses the active target unless path is given.",
            "See what kind of AI model a file holds and how big it is, without loading it.",
            Toolset::Formats,
            e,
            Requires::Nothing,
            schema_of::<ModelParams>,
            formats_ai_weights_show,
        ),
        spec(
            "app_builds_line_up",
            "Match functions between two builds",
            "Pair the functions of two builds of a program (two absolute paths) with the built-in engine. In order: unique names that aren't generated; identical bytes; bytes with addresses masked out; a structural fingerprint of block count, called names and referenced strings. Each pair says how it was matched, with what confidence, and what comparing the bodies found: a pair by name is still reported as changed when its code differs. Candidates that can't be told apart stay unpaired and are listed as ambiguous. Lists are paged together (offset/limit); show picks one; detail=summary keeps every row for core_evidence_browse. Nothing is executed. Takes as long as analysing both programs.",
            "Line up the functions of an old and a new version of a program, to see what changed.",
            Toolset::Native,
            e,
            Requires::Nothing,
            schema_of::<MatchParams>,
            app_builds_line_up,
        ),
        spec(
            "native_source_folder_write",
            "Write pseudo-C to a folder",
            "Write the built-in analysis's discovered functions as pseudo-C files, using the Deep engine when available or the built-in fallback. The state records the target SHA-256, chosen engine policy and each file's actual engine/provenance; resume skips only files that still exist. New exports default to auto; legacy exports resume with builtin. Set unlimited to remove per-call function/time budgets; discovery, per-function and 64 MiB checkpoint resource bounds still apply. Files and checkpoints are atomic; other targets, policy switches and occupied unrelated folders are refused.",
            "Save a whole program as readable code files, a part at a time.",
            Toolset::Native,
            Effects::MUTATES_SESSION | Effects::WRITES_FILESYSTEM | Effects::CARRIES_TARGET_CONTENT | Effects::LAUNCHES_PROCESS,
            Requires::Target,
            schema_of::<ExportCodeParams>,
            native_source_folder_write,
        ),
    ]
}

fn d_limit() -> usize {
    super::native_common::DEFAULT_LIMIT
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    /// Absolute path of the program; the active target when omitted.
    #[serde(default)]
    pub path: Option<String>,
    /// Keep rows whose name or library holds this text (any case).
    #[serde(default)]
    pub contains: Option<String>,
    /// Keep one kind: normal, delay, dynamic, weak, load, reexport, lazy, upward.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub offset: usize,
    /// Rows per page (1..=5000, default 200).
    #[serde(default = "d_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportParams {
    /// Absolute path of the program or library; the active target when omitted.
    #[serde(default)]
    pub path: Option<String>,
    /// Keep rows whose name or forwarder holds this text (any case).
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub offset: usize,
    /// Rows per page (1..=5000, default 200).
    #[serde(default = "d_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignerParams {
    /// Absolute path of the Windows program; the active target when omitted.
    #[serde(default)]
    pub path: Option<String>,
}

fn d_header_bytes() -> u64 {
    DEFAULT_HEADER_BYTES
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelParams {
    /// Absolute path of the model file; the active target when omitted.
    #[serde(default)]
    pub path: Option<String>,
    /// Most bytes read from the start of the file (1 KiB..4 GiB, default 256 MiB).
    #[serde(default = "d_header_bytes")]
    pub max_header_bytes: u64,
    #[serde(default)]
    pub offset: usize,
    /// Tensors per page (1..=5000, default 200).
    #[serde(default = "d_limit")]
    pub limit: usize,
    /// complete (default) or summary.
    #[serde(default)]
    pub detail: Detail,
}

/// Which list of a match to return.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchShow {
    #[default]
    All,
    Pairs,
    Changed,
    Ambiguous,
    OnlyLeft,
    OnlyRight,
}

fn d_match_bytes() -> u64 {
    DEFAULT_MATCH_BYTES
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchParams {
    /// Absolute path of the first (older) build.
    pub left: String,
    /// Absolute path of the second (newer) build.
    pub right: String,
    /// all (default), pairs, changed (pairs whose code differs), ambiguous, only_left or only_right.
    #[serde(default)]
    pub show: MatchShow,
    /// Refuse files bigger than this (up to 2 GiB, default 512 MiB).
    #[serde(default = "d_match_bytes")]
    pub max_file_bytes: u64,
    #[serde(default)]
    pub offset: usize,
    /// Rows per list (1..=5000, default 200).
    #[serde(default = "d_limit")]
    pub limit: usize,
    /// complete (default) returns the page; summary keeps every row for core_evidence_browse.
    #[serde(default)]
    pub detail: Detail,
}

fn d_max_functions() -> usize {
    1000
}

fn d_max_seconds() -> u64 {
    120
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportPolicy {
    /// Prefer the Deep engine and fall back to the built-in lifter.
    Auto,
    /// Use only the built-in lifter, including when resuming a legacy export.
    Builtin,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportCodeParams {
    /// Open target (document) to use; the active one when omitted.
    #[serde(default)]
    pub document: Option<String>,
    /// Absolute path of the folder to write to: new or empty, or one an earlier run of this tool wrote.
    pub folder: String,
    /// Most functions to write in this call (positive, default 1000); ignored when unlimited.
    #[serde(default = "d_max_functions")]
    pub max_functions: usize,
    /// Stop starting new functions after this many seconds (default 120); zero starts none.
    #[serde(default = "d_max_seconds")]
    pub max_seconds: u64,
    /// Remove the per-call function/time budgets; cancellation and analysis resource bounds remain.
    #[serde(default)]
    pub unlimited: bool,
    /// New folders default to auto; existing folders keep their saved policy when omitted.
    /// A different explicit policy requires a new folder.
    #[serde(default)]
    pub engine: Option<ExportPolicy>,
}

fn holds(text: &str, needle_lower: &str) -> bool {
    text.to_lowercase().contains(needle_lower)
}

fn notes_limitation(notes: &[String]) -> Option<Limitation> {
    (!notes.is_empty()).then(|| Limitation::new("reader_notes", notes.join("; ")))
}

fn page_coverage(mut cov: Coverage, truncated: bool) -> Coverage {
    if truncated {
        cov.status = CoverageStatus::Partial;
    }
    cov
}

fn slice_limitation(b: &Binary) -> Option<Limitation> {
    (b.slice_offset != 0).then(|| Limitation::new("one_slice", format!("This is a universal file; only its {} part was read.", b.arch.name())))
}

// ---------------------------------------------------------------------------------------------
// Imports

/// One imported function, whatever the file format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct ImportEntry {
    library: Option<String>,
    kind: String,
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ordinal: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    bound: bool,
}

#[derive(Default)]
struct ImportFacts {
    rows: Vec<ImportEntry>,
    /// Libraries with how they're linked, even those no row names.
    libraries: BTreeMap<String, BTreeSet<String>>,
    bound_modules: Value,
    truncated: bool,
    notes: Vec<String>,
}

fn pe_import_facts(data: &[u8]) -> Result<ImportFacts, ToolError> {
    let h = pe::headers(data).map_err(|e| format_err(e, "a Windows program"))?;
    let t = pe::import_table(data, &h);
    let mut f = ImportFacts { truncated: t.truncated, notes: t.warnings, bound_modules: json!(t.bound_modules), ..ImportFacts::default() };
    for r in t.rows {
        f.libraries.entry(r.library.clone()).or_default().insert(r.kind.name().to_string());
        f.rows.push(ImportEntry {
            library: Some(r.library),
            kind: r.kind.name().to_string(),
            name: r.name,
            ordinal: r.ordinal,
            hint: r.hint,
            slot: r.slot_va.map(|a| format!("{a:#x}")),
            version: None,
            bound: r.bound,
        });
    }
    Ok(f)
}

fn elf_import_facts(data: &[u8], b: &Binary) -> ImportFacts {
    let mut f = ImportFacts::default();
    for lib in &b.libraries {
        f.libraries.entry(lib.clone()).or_default().insert("needed".to_string());
    }
    let plain = |name: String, library: Option<String>, kind: &str, version: Option<String>| ImportEntry {
        library,
        kind: kind.to_string(),
        name: Some(name),
        ordinal: None,
        hint: None,
        slot: None,
        version,
        bound: false,
    };
    match elf::dynamic_symbols(data, b) {
        Some(s) => {
            f.truncated = s.truncated;
            f.notes = s.warnings;
            for i in s.imports {
                let kind = if i.binding == "weak" { "weak" } else { "dynamic" };
                f.rows.push(plain(i.name, i.library, kind, i.version));
            }
        }
        None => {
            f.notes.push("The file has no named dynamic symbol section, so versions weren't read.".into());
            f.rows.extend(b.imports.iter().map(|i| plain(i.name.clone(), i.library.clone(), "dynamic", None)));
        }
    }
    f
}

fn macho_import_facts(data: &[u8], b: &Binary) -> ImportFacts {
    let mut f = ImportFacts::default();
    let slice = usize::try_from(b.slice_offset).ok().and_then(|o| data.get(o..)).unwrap_or(data);
    let mut linked: BTreeMap<String, &'static str> = BTreeMap::new();
    match macho_deps::parse_thin(slice) {
        Ok(d) => {
            for lib in &d.dylibs {
                linked.insert(lib.name.clone(), lib.kind);
                f.libraries.entry(lib.name.clone()).or_default().insert(lib.kind.to_string());
            }
        }
        Err(e) => f.notes.push(format!("Load commands weren't read: {e}")),
    }
    for lib in &b.libraries {
        f.libraries.entry(lib.clone()).or_default();
    }
    for i in &b.imports {
        let kind = i.library.as_ref().and_then(|l| linked.get(l)).copied().unwrap_or("dynamic");
        f.rows.push(ImportEntry {
            library: i.library.clone(),
            kind: kind.to_string(),
            name: Some(i.name.clone()),
            ordinal: None,
            hint: None,
            slot: i.slot.map(|a| format!("{a:#x}")),
            version: None,
            bound: false,
        });
    }
    f
}

fn native_library_calls_list(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: ListParams = parse_params(params)?;
    let input = static_input::load(ctx, p.path.as_deref(), MAX_PROGRAM)?;
    let b = parse_binary(&input.bytes).map_err(|e| format_err(e, "a program"))?;
    let mut facts = match b.format {
        Format::Pe => pe_import_facts(&input.bytes)?,
        Format::Elf => elf_import_facts(&input.bytes, &b),
        Format::MachO => macho_import_facts(&input.bytes, &b),
        other => {
            return Err(
                ToolError::unsupported(format!("{} files don't list imports here.", other.plain())).with_remediation("Pass an ELF, PE or Mach-O program.")
            );
        }
    };
    facts.rows.sort();
    let total = facts.rows.len();
    let needle = p.contains.as_deref().map(str::to_lowercase);
    let kind = p.kind.as_deref();
    let rows: Vec<&ImportEntry> = facts
        .rows
        .iter()
        .filter(|r| kind.is_none_or(|k| r.kind == k))
        .filter(|r| needle.as_deref().is_none_or(|n| r.name.as_deref().is_some_and(|x| holds(x, n)) || r.library.as_deref().is_some_and(|x| holds(x, n))))
        .collect();
    let mut per_library: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for r in &facts.rows {
        let slot = per_library.entry(r.library.as_deref().unwrap_or("")).or_insert((0, 0));
        slot.0 += 1;
        slot.1 += usize::from(r.ordinal.is_some() && r.name.is_none());
    }
    let libraries: Vec<Value> = facts
        .libraries
        .iter()
        .map(|(name, kinds)| {
            let (count, ordinals) = per_library.get(name.as_str()).copied().unwrap_or((0, 0));
            json!({"name": name, "kinds": kinds, "imports": count, "by_ordinal_only": ordinals})
        })
        .collect();
    let (items, cov) = page(&rows, p.offset, p.limit);
    let delay = facts.rows.iter().filter(|r| r.kind == "delay").count();
    let delay_note = if delay > 0 { format!(", {delay} of them delay-loaded") } else { String::new() };
    let summary = format!("{total} imported function(s) from {} librar{}{delay_note}.", libraries.len(), if libraries.len() == 1 { "y" } else { "ies" });
    let mut e = builder(ctx, "native_library_calls_list", input.subject.clone(), params_json(&p))
        .result(json!({"path": input.path, "format": b.format, "total": total, "matching": rows.len(), "libraries": libraries, "imports": items, "bound_modules": facts.bound_modules}))
        .summary(summary)
        .confidence(Confidence::Observed)
        .authority(Authority::OriginalFiles)
        .target_content(true)
        .coverage(page_coverage(cov, facts.truncated))
        .location(Location::new("path", input.path.display().to_string()));
    if facts.truncated {
        e = e.limitation(Limitation::new("list_capped", "The file declares more imports than are kept from one file; the list stops there."));
    }
    if let Some(l) = notes_limitation(&facts.notes) {
        e = e.limitation(l);
    }
    if let Some(l) = slice_limitation(&b) {
        e = e.limitation(l);
    }
    if total == 0 {
        e = e.limitation(Limitation::new(
            "absence_not_proof",
            "Listing no imports doesn't mean the program uses no libraries: it can load them while it runs, by name, which leaves no entry here.",
        ));
    }
    Ok(ToolOutput::evidence(e.build()?))
}

// ---------------------------------------------------------------------------------------------
// Exports

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExportEntry {
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    forwarder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

fn native_offered_symbols_list(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: ExportParams = parse_params(params)?;
    let input = static_input::load(ctx, p.path.as_deref(), MAX_PROGRAM)?;
    let data: &[u8] = &input.bytes;
    let b = parse_binary(data).map_err(|e| format_err(e, "a program"))?;
    let plain = |name: String, addr: u64| ExportEntry {
        name: Some(name),
        ordinal: None,
        address: Some(format!("{addr:#x}")),
        forwarder: None,
        kind: None,
        binding: None,
        version: None,
        size: None,
    };
    let mut rows = Vec::new();
    let mut truncated = false;
    let mut notes = Vec::new();
    let mut extra = json!({});
    match b.format {
        Format::Pe => {
            let h = pe::headers(data).map_err(|e| format_err(e, "a Windows program"))?;
            if let Some(t) = pe::export_table(data, &h) {
                truncated = t.truncated;
                notes = t.warnings;
                extra = json!({"library_name": t.dll_name, "ordinal_base": t.ordinal_base, "declared_functions": t.declared_functions, "declared_names": t.declared_names});
                for x in t.entries {
                    let address = x.forwarder.is_none().then(|| format!("{:#x}", h.image_base.wrapping_add(u64::from(x.rva))));
                    rows.push(ExportEntry {
                        name: x.name,
                        ordinal: Some(x.ordinal),
                        address,
                        forwarder: x.forwarder,
                        kind: None,
                        binding: None,
                        version: None,
                        size: None,
                    });
                }
            }
        }
        Format::Elf => match elf::dynamic_symbols(data, &b) {
            Some(s) => {
                truncated = s.truncated;
                notes = s.warnings;
                for x in s.exports {
                    rows.push(ExportEntry {
                        name: Some(x.name),
                        ordinal: None,
                        address: Some(format!("{:#x}", x.addr)),
                        forwarder: None,
                        kind: Some(x.kind),
                        binding: Some(x.binding),
                        version: x.version,
                        size: Some(x.size),
                    });
                }
            }
            None => {
                notes.push("The file has no named dynamic symbol section, so versions weren't read.".to_string());
                rows.extend(b.exports.iter().map(|x| plain(x.name.clone(), x.addr)));
            }
        },
        Format::MachO => rows.extend(b.exports.iter().map(|x| plain(x.name.clone(), x.addr))),
        other => {
            return Err(ToolError::unsupported(format!("{} files don't list exports here.", other.plain())).with_remediation("Pass an ELF, PE or Mach-O file."));
        }
    }
    let total = rows.len();
    let forwarded = rows.iter().filter(|r| r.forwarder.is_some()).count();
    let by_ordinal = rows.iter().filter(|r| r.name.is_none()).count();
    let needle = p.contains.as_deref().map(str::to_lowercase);
    let kept: Vec<&ExportEntry> = rows
        .iter()
        .filter(|r| needle.as_deref().is_none_or(|n| r.name.as_deref().is_some_and(|x| holds(x, n)) || r.forwarder.as_deref().is_some_and(|x| holds(x, n))))
        .collect();
    let (items, cov) = page(&kept, p.offset, p.limit);
    let mut parts = Vec::new();
    if forwarded > 0 {
        parts.push(format!("{forwarded} forwarded to other libraries"));
    }
    if by_ordinal > 0 {
        parts.push(format!("{by_ordinal} by ordinal only"));
    }
    let tail = if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) };
    let mut e = builder(ctx, "native_offered_symbols_list", input.subject.clone(), params_json(&p))
        .result(json!({"path": input.path, "format": b.format, "total": total, "matching": kept.len(), "forwarded": forwarded, "ordinal_only": by_ordinal, "details": extra, "exports": items}))
        .summary(format!("{total} export(s){tail}."))
        .confidence(Confidence::Observed)
        .authority(Authority::OriginalFiles)
        .target_content(true)
        .coverage(page_coverage(cov, truncated))
        .location(Location::new("path", input.path.display().to_string()));
    if truncated {
        e = e.limitation(Limitation::new("list_capped", "The file's export table couldn't be read to its end, or holds more than are kept from one file."));
    }
    if let Some(l) = notes_limitation(&notes) {
        e = e.limitation(l);
    }
    if let Some(l) = slice_limitation(&b) {
        e = e.limitation(l);
    }
    Ok(ToolOutput::evidence(e.build()?))
}

// ---------------------------------------------------------------------------------------------
// Signature block

/// The plain sentence for one signature: who, then only what was checked.
fn signature_sentence(s: &SignatureReport) -> String {
    let who = s.signer.as_ref().map_or_else(|| "an unnamed signer".to_string(), |c| c.subject.clone());
    let mut out = format!("Signed by {who}.");
    match s.file_hash {
        HashStatus::Matches => out.push_str(" The file's hash matches the signed hash."),
        HashStatus::Differs => {
            out.push_str(" The file's hash does NOT match the signed hash: the file changed after signing, or the signature came from another file.")
        }
        HashStatus::NotChecked => out.push_str(" The file's hash wasn't checked."),
    }
    match &s.signature_check {
        Verified::Valid => out.push_str(" The signature checks out against the certificate in the file."),
        Verified::Invalid => out.push_str(" The signature does NOT check out against the certificate in the file."),
        Verified::Unsupported { .. } => out.push_str(" The signature itself wasn't checked."),
    }
    out.push_str(" Whether Windows trusts that certificate wasn't checked.");
    out
}

fn native_publisher_show(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: SignerParams = parse_params(params)?;
    let input = static_input::load(ctx, p.path.as_deref(), MAX_PROGRAM)?;
    ctx.report(None, format!("Reading the signature block of {}", input.name));
    let h = pe::headers(&input.bytes).map_err(|e| format_err(e, "a Windows program"))?;
    let table: Option<CertTable> = authenticode::certificate_table(&input.bytes, &h);
    let signature = table.as_ref().and_then(|t| t.entries.iter().find_map(|x| x.signature.as_ref()));
    let summary = match (&table, signature) {
        (None, _) => "This file has no signature block.".to_string(),
        (Some(_), Some(s)) if s.parsed => signature_sentence(s),
        (Some(_), Some(_)) => "This file has a signature block, but it isn't well-formed, so nothing can be said about who signed it.".to_string(),
        (Some(t), None) if t.entries.is_empty() => "The file declares a signature block, but no entry could be read from it.".to_string(),
        (Some(_), None) => "The file's signature block holds no Authenticode signature.".to_string(),
    };
    let signed = signature.is_some_and(|s| s.parsed);
    let mut lims = Vec::new();
    if table.is_none() {
        lims.push(Limitation::new(
            "catalog_possible",
            "No signature block in the file doesn't prove it's unsigned to Windows: a system catalog may vouch for it from outside, which this can't see.",
        ));
    }
    if signed {
        lims.push(Limitation::new(
            "trust_not_checked",
            "Certificates were read from the file. They weren't checked against any trust store, for revocation, or against the current date, so a matching signature can still come from an untrusted or expired certificate.",
        ));
        lims.push(Limitation::new(
            "hash_method",
            "The file hash covers everything except the header checksum, the security directory entry and the certificate table. Windows hashes sections in order, so a file with unusual gaps between them could read as different here though Windows accepts it.",
        ));
    }
    if signature.is_some_and(|s| !s.unsigned_attributes.is_empty()) {
        lims.push(Limitation::new("attachments_not_read", "Timestamps and nested signatures attached to the signature are listed, not read or checked."));
    }
    if let Some(l) = table.as_ref().and_then(|t| notes_limitation(&t.warnings)) {
        lims.push(l);
    }
    let result = json!({
        "path": input.path,
        "has_signature_block": table.is_some(),
        "signed": signed,
        "file_hash": signature.map(|s| s.file_hash),
        "signature_check": signature.map(|s| &s.signature_check),
        "signer": signature.and_then(|s| s.signer.as_ref()),
        "table": table,
    });
    let mut b = builder(ctx, "native_publisher_show", input.subject.clone(), params_json(&p))
        .result(result)
        .summary(summary)
        .confidence(Confidence::Observed)
        .authority(Authority::OriginalFiles)
        .target_content(true)
        .limitations(lims)
        .coverage(Coverage::complete(1))
        .location(Location::new("path", input.path.display().to_string()));
    if let Some(t) = &table {
        b = b.location(Location::new("file_offset", format!("{:#x}", t.file_offset)).with_label("certificate table"));
    }
    Ok(ToolOutput::evidence(b.build()?))
}

// ---------------------------------------------------------------------------------------------
// AI models

fn native_format_name(f: ai_model::ModelFormat) -> &'static str {
    match f {
        ai_model::ModelFormat::Gguf => "GGUF",
        ai_model::ModelFormat::Safetensors => "safetensors",
    }
}

fn formats_ai_weights_show(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: ModelParams = parse_params(params)?;
    if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&p.max_header_bytes) {
        return Err(ToolError::invalid(format!("max_header_bytes must be between {MIN_HEADER_BYTES} and {MAX_HEADER_BYTES}")));
    }
    let input = static_input::load_prefix(ctx, p.path.as_deref(), p.max_header_bytes)?;
    let mut r = ai_model::parse(&input.bytes, input.file_size).map_err(|e| match e {
        craft_anything_formats::FormatError::TooLarge(m) => {
            ToolError::new(ErrorCode::OverLimit, format!("Couldn't read this model's header: {m}")).with_remediation("Raise max_header_bytes (up to 4 GiB).")
        }
        other => format_err(other, "a GGUF or safetensors model"),
    })?;
    let tensors = std::mem::take(&mut r.tensors);
    // summary keeps every tensor, for core_evidence_browse; complete returns the asked-for page.
    let (items, cov) = if p.detail == Detail::Summary {
        let all: Vec<Value> = tensors.iter().map(|t| serde_json::to_value(t).unwrap_or(Value::Null)).collect();
        let n = all.len() as u64;
        (all, Coverage::complete(n))
    } else {
        page(&tensors, p.offset, p.limit)
    };
    let arch = r.architecture.as_deref().map_or_else(|| "A model with no recorded architecture".to_string(), |a| format!("A {a} model"));
    let quant = r.quantization.as_deref().map_or_else(String::new, |q| format!(", quantized as {q}"));
    let summary = format!(
        "{arch} in {} format: about {} parameters in {} tensors{quant}.",
        native_format_name(r.format),
        ai_model::plain_count(r.parameters),
        r.tensors_read,
    );
    let mut lims = vec![Limitation::new("tensor_data_not_read", "Only the header was read. Whether the tensor data is really there and sound wasn't checked.")];
    if !input.whole {
        lims.push(Limitation::new(
            "part_of_file_read",
            format!("Only the first {} of {} bytes were read, so this record's identity has no SHA-256 for the file.", input.bytes.len(), input.file_size),
        ));
    }
    if !r.complete {
        lims.push(Limitation::new(
            "header_incomplete",
            "The header wasn't read to its end: tensors and metadata listed may not be all of them, and the totals count only what was read.",
        ));
    }
    if let Some(l) = notes_limitation(&r.warnings) {
        lims.push(l);
    }
    if r.format == ai_model::ModelFormat::Safetensors && r.architecture.is_none() {
        lims.push(Limitation::new("architecture_not_recorded", "safetensors files need not say what model they hold, and this one doesn't."));
    }
    let extras = json!({"format": r.format, "architecture": r.architecture, "parameters": r.parameters, "tensors": r.tensors_read, "complete": r.complete});
    let confidence = if r.complete { Confidence::Observed } else { Confidence::Inferred };
    let mut coverage = cov;
    if !r.complete {
        coverage.status = CoverageStatus::Partial;
    }
    let e = builder(ctx, "formats_ai_weights_show", input.subject.clone(), params_json(&p))
        .result(json!({"path": input.path, "bytes_read": input.bytes.len(), "report": r, "tensors": items}))
        .summary(summary)
        .confidence(confidence)
        .authority(Authority::OriginalFiles)
        .target_content(true)
        .limitations(lims)
        .coverage(coverage)
        .location(Location::new("path", input.path.display().to_string()))
        .build()?;
    detailed(ctx, e, p.detail, extras)
}

// ---------------------------------------------------------------------------------------------
// Matching two builds

fn analyse_side(ctx: &Ctx<'_>, path: &str, max: u64, side: &str) -> Result<(static_input::Input, Image, Program), ToolError> {
    let input = static_input::load_path(path, max)?;
    ctx.report(None, format!("Analysing the {side} build, {}", input.name));
    let img = Image::parse(input.bytes.clone()).map_err(disasm_err)?;
    let prog = Program::analyze(&img, &Limits::default(), &CtxControl::of(ctx)).map_err(disasm_err)?;
    Ok((input, img, prog))
}

/// Functions under the size where a body says enough to pair on: small stubs often stay listed on
/// both sides though nothing happened to them.
fn too_small(rows: &[function_match::FunctionRef]) -> usize {
    rows.iter().filter(|f| f.size < function_match::MIN_BODY_BYTES).count()
}

fn is_changed(p: &MatchedPair) -> bool {
    p.body == BodyStatus::Changed
}

fn method_counts(r: &MatchResult) -> Value {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in [MatchMethod::ExactName, MatchMethod::IdenticalBytes, MatchMethod::MaskedBytes, MatchMethod::Structure] {
        counts.insert(m.name(), r.pairs.iter().filter(|p| p.method == m).count());
    }
    json!(counts)
}

fn app_builds_line_up(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    let p: MatchParams = parse_params(params)?;
    if p.max_file_bytes > MAX_PROGRAM {
        return Err(ToolError::invalid(format!("max_file_bytes can be at most {MAX_PROGRAM}")));
    }
    let (left, limg, lprog) = analyse_side(ctx, &p.left, p.max_file_bytes, "first")?;
    ctx.cancel.check()?;
    let (right, rimg, rprog) = analyse_side(ctx, &p.right, p.max_file_bytes, "second")?;
    ctx.cancel.check()?;
    let r = function_match::match_programs((&limg, &lprog), (&rimg, &rprog), &CtxControl::of(ctx)).map_err(disasm_err)?;

    let changed: Vec<&MatchedPair> = r.pairs.iter().filter(|x| is_changed(x)).collect();
    let unchanged = r.pairs.iter().filter(|x| matches!(x.body, BodyStatus::Identical | BodyStatus::SameApartFromAddresses)).count();
    let not_compared = r.pairs.iter().filter(|x| x.body == BodyStatus::NotCompared).count();
    let renamed = r.pairs.iter().filter(|x| x.renamed).count();
    let weak = r.pairs.iter().filter(|x| x.method == MatchMethod::Structure).count();
    let summary = format!(
        "Paired {} of {} and {} functions: {unchanged} unchanged, {} changed{}{}. Left unpaired: {} ambiguous group(s), {} only in the first build, {} only in the second.",
        r.pairs.len(),
        lprog.functions.len(),
        rprog.functions.len(),
        changed.len(),
        if not_compared > 0 { format!(", {not_compared} not compared") } else { String::new() },
        if renamed > 0 { format!(", {renamed} renamed") } else { String::new() },
        r.ambiguous.len(),
        r.only_left.len(),
        r.only_right.len(),
    );
    let counts = json!({
        "left_functions": lprog.functions.len(),
        "right_functions": rprog.functions.len(),
        "pairs": r.pairs.len(),
        "by_method": method_counts(&r),
        "unchanged": unchanged,
        "changed": changed.len(),
        "not_compared": not_compared,
        "renamed": renamed,
        "ambiguous_groups": r.ambiguous.len(),
        "only_left": r.only_left.len(),
        "only_right": r.only_right.len(),
        "only_left_too_small_to_pair": too_small(&r.only_left),
        "only_right_too_small_to_pair": too_small(&r.only_right),
    });

    // summary keeps every row, for core_evidence_browse; complete returns the asked-for page.
    let (offset, limit) = if p.detail == Detail::Summary { (0, usize::MAX) } else { (p.offset, p.limit.clamp(1, super::native_common::MAX_LIMIT)) };
    let window = |rows: Vec<Value>| -> (Vec<Value>, usize) {
        let total = rows.len();
        (rows.into_iter().skip(offset).take(limit).collect(), total)
    };
    let to_values = |rows: Vec<Value>| window(rows);
    let wants = |s: MatchShow| p.show == MatchShow::All || p.show == s;
    let mut result = json!({
        "left": {"path": left.path, "sha256": left.subject.sha256, "processor": lprog.mode.name()},
        "right": {"path": right.path, "sha256": right.subject.sha256, "processor": rprog.mode.name()},
        "counts": counts,
    });
    let mut examined = 0usize;
    let mut more = false;
    let mut add = |key: &str, rows: Vec<Value>| {
        let (page_rows, total) = to_values(rows);
        examined += page_rows.len();
        more |= offset.saturating_add(page_rows.len()) < total;
        if let Value::Object(m) = &mut result {
            m.insert(key.to_string(), Value::Array(page_rows));
        }
    };
    let as_json = |x: &[&MatchedPair]| x.iter().map(|v| serde_json::to_value(v).unwrap_or(Value::Null)).collect::<Vec<_>>();
    if p.show == MatchShow::Changed {
        add("pairs", as_json(&changed));
    } else if wants(MatchShow::Pairs) {
        add("pairs", as_json(&r.pairs.iter().collect::<Vec<_>>()));
    }
    if wants(MatchShow::Ambiguous) {
        add("ambiguous", r.ambiguous.iter().map(|v| serde_json::to_value(v).unwrap_or(Value::Null)).collect());
    }
    if wants(MatchShow::OnlyLeft) {
        add("only_left", r.only_left.iter().map(|v| serde_json::to_value(v).unwrap_or(Value::Null)).collect());
    }
    if wants(MatchShow::OnlyRight) {
        add("only_right", r.only_right.iter().map(|v| serde_json::to_value(v).unwrap_or(Value::Null)).collect());
    }

    let capped = lprog.discovery_capped() || rprog.discovery_capped();
    let mut coverage = Coverage {
        status: if more || capped { CoverageStatus::Partial } else { CoverageStatus::Complete },
        examined: Some(examined as u64),
        total: None,
        next_offset: more.then(|| offset.saturating_add(limit) as u64),
    };
    if !more && !capped {
        coverage.total = Some(examined as u64);
    }
    let mut lims = vec![
        Limitation::new(
            "changed_may_be_addresses",
            "\"changed\" means the bytes differ after the address fields the engine recognises are masked. An address built in a way it doesn't follow (across blocks, say) stays unmasked, so a changed function can be the same code moved. x86 and arm64 are masked; other processors compare exact bytes only.",
        ),
        Limitation::new(
            "same_name_not_same_code",
            "An exact-name pair says two functions correspond, not that the code is the same; read each pair's body field. \"unchanged\" compares this function's instructions, what it calls by name and the strings it uses, not the data it reads or how the functions it calls behave.",
        ),
        Limitation::new(
            "unpaired_not_removed",
            "A function listed on one side only isn't proof that it was added or removed: it may have been renamed and rewritten, inlined, split, not found by the analysis, or too small and unnamed to pair (bodies under 16 bytes aren't paired on bytes; counts has how many).",
        ),
    ];
    if weak > 0 {
        lims.push(Limitation::new(
            "structural_pairs_are_guesses",
            format!("{weak} pair(s) rest only on block count, called names and strings; two different functions can share those."),
        ));
    }
    if capped {
        lims.push(Limitation::new("discovery_capped", "Function discovery hit a limit on at least one side, so some functions weren't considered."));
    }
    if lprog.mode != rprog.mode {
        lims.push(Limitation::new(
            "different_processors",
            format!(
                "The builds are for different processors ({} and {}), so only names were matched and no bodies were compared.",
                lprog.mode.name(),
                rprog.mode.name()
            ),
        ));
    }
    let e = builder(ctx, "app_builds_line_up", right.subject.clone(), params_json(&p))
        .result(result)
        .summary(summary)
        .confidence(if weak > 0 { Confidence::Inferred } else { Confidence::Derived })
        .authority(Authority::OriginalFiles)
        .target_content(true)
        .limitations(lims)
        .coverage(coverage)
        .location(Location::new("path", left.path.display().to_string()).with_label("first build"))
        .location(Location::new("path", right.path.display().to_string()).with_label("second build"))
        .build()?;
    detailed(ctx, e, p.detail, json!({"counts": counts}))
}

// ---------------------------------------------------------------------------------------------
// Writing pseudo-C across runs

/// The state file's name inside an export folder.
pub const EXPORT_STATE_FILE: &str = "craft-pseudocode-export.json";
/// The state file's format version.
const EXPORT_STATE_VERSION: u32 = 2;
/// Save the state at least this often, so a crash costs little repeated work.
const SAVE_EVERY_FUNCTIONS: usize = 256;
const SAVE_EVERY: Duration = Duration::from_secs(5);
/// Most newly written file names listed in one result.
const MAX_LISTED: usize = 200;
/// Bounds resume parsing and checkpoint serialization, independently of workflow budgets.
const MAX_EXPORT_STATE_BYTES: usize = 64 * 1024 * 1024;

/// One function that has been written.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ExportedFunction {
    file: String,
    name: String,
    lines: usize,
    structured: Option<bool>,
    engine: String,
    /// Older exports did not save these details; migration does not invent them.
    provenance: Option<ExportProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportProvenance {
    entry: Option<String>,
    environment: Environment,
    confidence: Confidence,
    authority: Authority,
    limitations: Vec<Limitation>,
}

// Evidence's L0 types intentionally have no schema dependency. Describe the metadata we retain
// here without adding a dependency to that layer or weakening these fields to arbitrary JSON.
impl JsonSchema for ExportProvenance {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ExportProvenance".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "properties": {
                "entry": {"type": ["string", "null"]},
                "environment": {
                    "type": "object",
                    "properties": {
                        "clean_room": {"type": "boolean"},
                        "engine": {"type": "string"},
                        "engine_version": {"type": ["string", "null"]},
                        "host": {"type": "string"},
                        "language_id": {"type": ["string", "null"]}
                    },
                    "required": ["clean_room", "engine", "host"]
                },
                "confidence": {"enum": [Confidence::Observed, Confidence::Derived, Confidence::Inferred]},
                "authority": {"enum": [Authority::OriginalFiles, Authority::OurRun, Authority::EarlierRecord, Authority::OutsideService, Authority::Reasoning]},
                "limitations": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"code": {"type": "string"}, "message": {"type": "string"}}, "required": ["code", "message"]}
                }
            },
            "required": ["environment", "confidence", "authority", "limitations"]
        })
    }
}

/// What an export folder holds, by function entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ExportState {
    version: u32,
    target_sha256: String,
    target_name: String,
    policy: ExportPolicy,
    functions: BTreeMap<String, ExportedFunction>,
}

/// The schema of the versioned state beside exported pseudo-C files.
pub fn source_export_schema() -> String {
    let schema = schemars::generate::SchemaSettings::draft2020_12().into_generator().into_root_schema_for::<ExportState>();
    serde_json::to_string_pretty(&schema).map(|s| s + "\n").unwrap_or_default()
}

/// A file name that's safe everywhere, whatever a hostile program calls its function: the entry
/// address keeps it unique and the name is only a readable hint.
fn export_file_name(entry: u64, name: &str) -> String {
    let safe: String = name.chars().filter(char::is_ascii).map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).take(64).collect();
    let safe = safe.trim_matches('_');
    if safe.is_empty() { format!("{entry:016x}.c") } else { format!("{entry:016x}_{safe}.c") }
}

/// A name inside a one-line comment: nothing in it can end the comment's line.
fn comment_safe(name: &str) -> String {
    name.chars().map(|c| if c.is_control() { ' ' } else { c }).take(512).collect()
}

/// Read the state of an existing folder, or start one in a new or empty folder. Refuses a folder
/// with anything else in it, another target's export, and a state it can't read.
fn open_export_state(folder: &Path, sha: &str, target: &str, requested: Option<ExportPolicy>, state_limit: usize) -> Result<ExportState, ToolError> {
    let state_path = folder.join(EXPORT_STATE_FILE);
    let fresh = || ExportState {
        version: EXPORT_STATE_VERSION,
        target_sha256: sha.to_string(),
        target_name: target.to_string(),
        policy: requested.unwrap_or(ExportPolicy::Auto),
        functions: BTreeMap::new(),
    };
    if folder.exists() && !folder.is_dir() {
        return Err(ToolError::invalid(format!("{} is a file, not a folder", folder.display())));
    }
    if !state_path.exists() {
        if folder.is_dir() {
            let mut entries = std::fs::read_dir(folder).map_err(|e| ToolError::io(folder.display(), e))?;
            if entries.next().is_some() {
                return Err(ToolError::invalid(format!("{} already has other files in it", folder.display()))
                    .with_remediation("Pick a new or empty folder, so nothing of yours is overwritten."));
            }
        }
        return Ok(fresh());
    }
    let file = std::fs::File::open(&state_path).map_err(|e| ToolError::io(state_path.display(), e))?;
    let read_limit = u64::try_from(state_limit).ok().and_then(|n| n.checked_add(1)).ok_or_else(|| ToolError::internal("Invalid export state byte limit."))?;
    let mut bytes = Vec::new();
    file.take(read_limit).read_to_end(&mut bytes).map_err(|e| ToolError::io(state_path.display(), e))?;
    if bytes.len() > state_limit {
        return Err(export_state_limit(state_limit));
    }
    let unreadable = |why: String| {
        ToolError::invalid(format!("Couldn't read the state file {}: {why}", state_path.display()))
            .with_remediation("Pick a new folder; this one is left as it is.")
    };
    let mut raw: Value = serde_json::from_slice(&bytes).map_err(|e| unreadable(e.to_string()))?;
    let version = raw.get("version").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or_else(|| unreadable("it has no valid version".into()))?;
    let reached = crate::versioned::upgrade(&mut raw, version, 1, &[export_v1_to_v2]).map_err(unreadable)?;
    if let Some(table) = raw.as_object_mut() {
        table.insert("version".into(), json!(reached));
    }
    let state: ExportState = serde_json::from_value(raw).map_err(|e| unreadable(e.to_string()))?;
    if state.target_sha256 != sha {
        return Err(ToolError::invalid(format!("{} holds an export of a different file ({})", folder.display(), state.target_name))
            .with_remediation("Pick a new folder for this target, or open the file this export belongs to.")
            .with_details(json!({"reason": "different_target", "folder_target_sha256": state.target_sha256, "target_sha256": sha})));
    }
    if requested.is_some_and(|policy| policy != state.policy) {
        return Err(ToolError::invalid("This export already uses a different engine policy.")
            .with_remediation("Leave engine unset to continue this export, or choose a new folder for the new policy.")
            .with_details(json!({"reason": "export_policy_mismatch", "saved": state.policy, "requested": requested})));
    }
    let mut files = BTreeSet::new();
    for (key, record) in &state.functions {
        let entry = key.strip_prefix("0x").and_then(|hex| u64::from_str_radix(hex, 16).ok()).filter(|entry| format!("{entry:#x}") == *key);
        let Some(entry) = entry else {
            return Err(unreadable("a recorded function has an invalid entry address".into()));
        };
        if record.file == EXPORT_STATE_FILE || record.file != export_file_name(entry, &record.name) || !files.insert(&record.file) {
            return Err(unreadable("a recorded output does not match its function's generated file name, or is reserved or repeated".into()));
        }
    }
    Ok(state)
}

fn export_v1_to_v2(raw: &mut Value) -> Result<(), String> {
    let table = raw.as_object_mut().ok_or("the state is not an object")?;
    if table.remove("engine").as_ref().and_then(Value::as_str) != Some("clean-room lifter") {
        return Err("the legacy export did not name the built-in lifter".into());
    }
    table.insert("policy".into(), json!(ExportPolicy::Builtin));
    let functions = table.get_mut("functions").and_then(Value::as_object_mut).ok_or("the state has no function table")?;
    for function in functions.values_mut() {
        let fields = function.as_object_mut().ok_or("a function record is not an object")?;
        fields.insert("engine".into(), json!("clean-room lifter"));
        fields.insert("provenance".into(), Value::Null);
    }
    Ok(())
}

fn export_state_limit(limit: usize) -> ToolError {
    ToolError::new(ErrorCode::OverLimit, format!("The export checkpoint exceeds its {limit}-byte resource limit."))
        .with_remediation("Existing outputs and the checkpoint are retained. Unlimited removes workflow budgets, not this storage resource bound.")
}

/// Count JSON bytes or collect them, refusing a write before it crosses the budget. Counting
/// has no output buffer; collecting reserves only the bytes the serializer actually writes.
struct ExportJson<'a> {
    output: Option<&'a mut Vec<u8>>,
    used: usize,
    limit: usize,
    exceeded: bool,
}

impl Write for ExportJson<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.used.checked_add(bytes.len()).filter(|next| *next <= self.limit) else {
            self.exceeded = true;
            return Err(std::io::Error::other("export state byte limit"));
        };
        if let Some(output) = &mut self.output {
            output.try_reserve(bytes.len()).map_err(std::io::Error::other)?;
            output.extend_from_slice(bytes);
        }
        self.used = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_export_json(value: &impl Serialize, writer: &mut ExportJson<'_>) -> Result<(), ToolError> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        if writer.exceeded { export_state_limit(writer.limit) } else { ToolError::invalid(format!("Couldn't serialize export state: {error}")) }
    })
}

fn export_json_size(value: &impl Serialize, limit: usize) -> Result<usize, ToolError> {
    let mut writer = ExportJson { output: None, used: 0, limit, exceeded: false };
    write_export_json(value, &mut writer)?;
    Ok(writer.used)
}

/// An entry inside a compact JSON map: quoted key, colon, value. Commas are counted separately.
fn export_entry_size(key: &str, record: &ExportedFunction, limit: usize) -> Result<usize, ToolError> {
    let mut writer = ExportJson { output: None, used: 0, limit, exceeded: false };
    write_export_json(&key, &mut writer)?;
    writer.write_all(b":").map_err(|_| export_state_limit(limit))?;
    write_export_json(record, &mut writer)?;
    Ok(writer.used)
}

/// Exact incremental accounting avoids serializing an ever-growing checkpoint for every
/// function. Only the new and (when replaced) old map entry are examined for admission.
fn export_record_size(state: &ExportState, used: usize, key: &str, record: &ExportedFunction, limit: usize) -> Result<Option<usize>, ToolError> {
    let added = match export_entry_size(key, record, limit) {
        Err(error) if error.code == ErrorCode::OverLimit => return Ok(None),
        result => result?,
    };
    let existing = state.functions.get(key);
    let removed = existing.map(|old| export_entry_size(key, old, limit)).transpose()?.unwrap_or(0);
    let remaining = used.checked_sub(removed).ok_or_else(|| ToolError::internal("Export checkpoint byte accounting is inconsistent."))?;
    let comma = usize::from(existing.is_none() && !state.functions.is_empty());
    Ok(remaining.checked_add(added).and_then(|next| next.checked_add(comma)).filter(|next| *next <= limit))
}

fn save_export_state(folder: &Path, state: &ExportState, limit: usize) -> Result<(), ToolError> {
    let mut bytes = Vec::new();
    let mut writer = ExportJson { output: Some(&mut bytes), used: 0, limit, exceeded: false };
    // Compact JSON keeps per-entry admission accounting exact; the versioned data is unchanged.
    write_export_json(state, &mut writer)?;
    write_atomic(&folder.join(EXPORT_STATE_FILE), &bytes)
}

fn native_source_folder_write(ctx: &mut Ctx<'_>, params: Value) -> Result<ToolOutput, ToolError> {
    source_folder_write_with_limit(ctx, params, MAX_EXPORT_STATE_BYTES)
}

fn source_folder_write_with_limit(ctx: &mut Ctx<'_>, params: Value, state_limit: usize) -> Result<ToolOutput, ToolError> {
    let p: ExportCodeParams = parse_params(params)?;
    select_document(ctx, &p.document)?;
    if !p.unlimited && p.max_functions == 0 {
        return Err(ToolError::invalid("max_functions must be positive unless unlimited is true"));
    }
    let folder = PathBuf::from(&p.folder);
    if !folder.is_absolute() {
        return Err(ToolError::invalid(format!("{:?} is not an absolute path", p.folder)).with_remediation("Pass the full path of a folder."));
    }
    // Refuse before the (possibly long) analysis or any writes.
    let (sha, target_name) = {
        let t = &ctx.session.active()?.target;
        (t.sha256.clone(), t.name.clone())
    };
    let mut state = open_export_state(&folder, &sha, &target_name, p.engine, state_limit)?;
    let mut state_bytes = export_json_size(&state, state_limit)?;
    // The candidate set remains the bounded built-in discovery. In particular, do not ask the
    // Deep bridge for its unpaged whole-program function list just to export the code it knows.
    let st = native(ctx)?;
    std::fs::create_dir_all(&folder).map_err(|e| ToolError::io(folder.display(), e))?;
    save_export_state(&folder, &state, state_limit)?;

    let total = st.prog.functions.len();
    let started = Instant::now();
    let limit = Duration::from_secs(p.max_seconds);
    let mut last_save = Instant::now();
    let mut unsaved = 0usize;
    let mut written_now = 0usize;
    let mut already_done = 0usize;
    let mut replaced_missing = 0usize;
    let mut listed = Vec::new();
    let mut stopped = "finished";
    let mut next_function = None;
    for (i, f) in st.prog.functions.values().enumerate() {
        if let Err(e) = ctx.cancel.check() {
            save_export_state(&folder, &state, state_limit)?;
            return Err(e);
        }
        let key = format!("{:#x}", f.entry);
        let missing = if let Some(done) = state.functions.get(&key) {
            if folder.join(&done.file).is_file() {
                already_done = already_done.saturating_add(1);
                continue;
            }
            true
        } else {
            false
        };
        if !p.unlimited && written_now >= p.max_functions {
            stopped = "max_functions";
            next_function = Some(key);
            break;
        }
        if !p.unlimited && started.elapsed() >= limit {
            stopped = "time_limit";
            next_function = Some(key);
            break;
        }
        if i % 64 == 0 {
            ctx.report(Some(i as f32 / total.max(1) as f32), format!("writing {}", f.name));
        }
        let input = super::native_function::ProcParams { document: None, function: key.clone() };
        let result = match state.policy {
            ExportPolicy::Auto => super::native_function::decompile(ctx, &input),
            ExportPolicy::Builtin => super::native_function::decompile_builtin(ctx, &input),
        };
        let evidence = match result {
            Ok(evidence) => evidence,
            Err(error) => {
                save_export_state(&folder, &state, state_limit)?;
                return Err(error);
            }
        };
        let code = evidence
            .result
            .get("pseudo_code")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| ToolError::new(ErrorCode::GarbledOutput, "The decompiler returned no code to export."))?;
        let name = evidence.result.get("function").and_then(Value::as_str).unwrap_or(&f.name).to_string();
        let actual_engine = evidence.result.get("engine").and_then(Value::as_str).unwrap_or(&evidence.environment.engine).to_string();
        let file = export_file_name(f.entry, &name);
        let text = format!(
            "// {} at {key}, from {}. Reconstructed pseudo-C from {}.\n{}\n",
            comment_safe(&name),
            comment_safe(&target_name),
            comment_safe(&actual_engine),
            code
        );
        let record = ExportedFunction {
            file,
            name,
            lines: code.lines().count(),
            structured: evidence.result.get("structured").and_then(Value::as_bool),
            engine: actual_engine,
            provenance: Some(ExportProvenance {
                entry: evidence.result.get("entry").and_then(Value::as_str).map(String::from),
                environment: evidence.environment,
                confidence: evidence.confidence,
                authority: evidence.authority,
                limitations: evidence.limitations,
            }),
        };
        let next_bytes = match export_record_size(&state, state_bytes, &key, &record, state_limit) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                stopped = "state_resource_limit";
                next_function = Some(key);
                break;
            }
            Err(error) => {
                save_export_state(&folder, &state, state_limit)?;
                return Err(error);
            }
        };
        // Admission happens before either the output or its state entry is changed: every file
        // we write can still be represented by a checkpoint that the resume reader accepts.
        if let Err(error) = write_atomic(&folder.join(&record.file), text.as_bytes()) {
            save_export_state(&folder, &state, state_limit)?;
            return Err(error);
        }
        if listed.len() < MAX_LISTED {
            listed.push(record.file.clone());
        }
        state.functions.insert(key, record);
        state_bytes = next_bytes;
        written_now = written_now.saturating_add(1);
        replaced_missing = replaced_missing.saturating_add(usize::from(missing));
        unsaved = unsaved.saturating_add(1);
        if unsaved >= SAVE_EVERY_FUNCTIONS || last_save.elapsed() >= SAVE_EVERY {
            save_export_state(&folder, &state, state_limit)?;
            unsaved = 0;
            last_save = Instant::now();
        }
    }
    save_export_state(&folder, &state, state_limit)?;
    ctx.cancel.check()?;

    // Count all candidates, including missing files after the per-call stopping point. A state
    // entry by itself is not proof that its output still exists.
    let present: Vec<&ExportedFunction> =
        st.prog.functions.keys().filter_map(|entry| state.functions.get(&format!("{entry:#x}")).filter(|record| folder.join(&record.file).is_file())).collect();
    let done = present.len();
    let engines: BTreeSet<&str> = present.iter().map(|record| record.engine.as_str()).collect();
    let remaining = total.saturating_sub(done);
    let finished = remaining == 0;
    let summary = if finished {
        format!("All {total} built-in-discovered candidates are written ({written_now} in this run, {already_done} from earlier runs).")
    } else if stopped == "state_resource_limit" {
        format!(
            "{done} of {total} built-in-discovered candidates are written. The checkpoint reached its resource limit; existing outputs are retained, and the next function was not written."
        )
    } else {
        format!(
            "{done} of {total} built-in-discovered candidates are written ({written_now} in this run); {remaining} remain. Run this again with the same folder to continue."
        )
    };
    let capped = st.prog.discovery_capped();
    let mut lims = vec![
        Limitation::new(
            "discovery_scope",
            "Candidates come from the bounded built-in analysis, not a complete Deep-engine function catalogue. Completion means these discovered candidates were written.",
        ),
        Limitation::new(
            "pseudo_code_inferred",
            "Pseudo-C is reconstructed code, not original source. Each exported file records its actual engine and provenance in the state file.",
        ),
    ];
    if capped {
        lims.push(Limitation::new("discovery_capped", "Built-in function discovery hit an analysis resource limit; other functions may remain undiscovered."));
    }
    if stopped == "state_resource_limit" {
        lims.push(Limitation::new(
            "export_state_limit",
            format!("The next function cannot fit the {state_limit}-byte checkpoint resource budget. Existing state and outputs remain resumable; unlimited does not remove this resource bound."),
        ));
    }
    let e = super::native_common::ev(ctx, "native_source_folder_write", params_json(&p))?
        .result(json!({
            "folder": folder,
            "state_file": EXPORT_STATE_FILE,
            "state_bytes": state_bytes,
            "state_byte_limit": state_limit,
            "target_sha256": sha,
            "engine_policy": state.policy,
            "engines_used": engines,
            "discovery": {"engine": "builtin", "scope": "discovered_candidates", "capped": capped, "limitations": st.prog.limitations},
            "functions_total": total,
            "functions_done": done,
            "written_now": written_now,
            "already_done": already_done,
            "replaced_missing": replaced_missing,
            "remaining": remaining,
            "finished": finished,
            "stopped_because": stopped,
            "next_function": next_function,
            "written_files": listed,
        }))
        .summary(summary)
        .confidence(Confidence::Inferred)
        .target_content(true)
        .limitations(lims)
        .coverage(Coverage {
            status: if finished && !capped { CoverageStatus::Complete } else { CoverageStatus::Partial },
            examined: Some(done as u64),
            total: Some(total as u64),
            next_offset: None,
        })
        .location(Location::new("path", folder.display().to_string()))
        .build()?;
    Ok(ToolOutput::evidence(e))
}

#[cfg(test)]
mod tests {
    use super::super::native_common::test_support::{call, call_err, engine_with};
    use super::*;
    use crate::{CallOptions, Caller, Engine};
    use craft_anything_testkit::program_facts as pf;
    use craft_anything_testkit::temp_file;

    fn engine() -> Engine {
        Engine::new(crate::testing::session())
    }

    fn limitation<'a>(v: &'a Value, code: &str) -> Option<&'a Value> {
        v["limitations"].as_array().and_then(|l| l.iter().find(|x| x["code"] == code))
    }

    #[test]
    fn deep_only_all_of_them() {
        // Clean room refuses each: they look inside the target.
        let e = engine();
        e.session().settings.deep_mode = false;
        let p = temp_file("a.bin", &pf::pe_facts());
        for (id, params) in [
            ("native_library_calls_list", json!({"path": p})),
            ("native_offered_symbols_list", json!({"path": p})),
            ("native_publisher_show", json!({"path": p})),
            ("formats_ai_weights_show", json!({"path": p})),
            ("app_builds_line_up", json!({"left": p, "right": p})),
        ] {
            assert!(crate::clean_room::is_refusal(&call_err(&e, id, params)), "{id}");
        }
    }

    #[test]
    fn pe_imports_grouped_with_kinds_and_filters() {
        let e = engine();
        let p = temp_file("facts.dll", &pf::pe_facts());
        let v = call(&e, "native_library_calls_list", json!({"path": p}));
        assert_eq!(v["confidence"], "observed");
        let r = &v["result"];
        let version = r["libraries"].as_array().unwrap().iter().find(|l| l["name"] == "VERSION.dll").unwrap();
        assert_eq!(version["kinds"], json!(["delay"]));
        assert_eq!(version["by_ordinal_only"], 1);
        let delayed = r["imports"].as_array().unwrap().iter().find(|i| i["name"] == "GetFileVersionInfoW").unwrap();
        assert_eq!(delayed["kind"], "delay");
        assert!(delayed["slot"].as_str().unwrap().starts_with("0x"));
        assert_eq!(r["bound_modules"][0]["name"], "USER32.dll");
        assert!(v["summary"].as_str().unwrap().contains("delay-loaded"));

        let v = call(&e, "native_library_calls_list", json!({"path": p, "contains": "createfile"}));
        assert_eq!(v["result"]["matching"], 1);
        assert_eq!(v["result"]["imports"][0]["hint"], 7);
        let v = call(&e, "native_library_calls_list", json!({"path": p, "kind": "delay"}));
        assert_eq!(v["result"]["matching"], 2);
        // A library's name matches too.
        let v = call(&e, "native_library_calls_list", json!({"path": p, "contains": "user32"}));
        assert_eq!(v["result"]["imports"][0]["bound"], true);
        // Pages.
        let v = call(&e, "native_library_calls_list", json!({"path": p, "limit": 2}));
        assert_eq!(v["result"]["imports"].as_array().unwrap().len(), 2);
        assert_eq!(v["coverage"]["status"], "partial");
        assert_eq!(v["coverage"]["next_offset"], 2);
        let v = call(&e, "native_library_calls_list", json!({"path": p, "offset": 1000}));
        assert!(v["result"]["imports"].as_array().unwrap().is_empty());
    }

    #[test]
    fn elf_and_macho_imports_and_exports() {
        let e = engine();
        let p = temp_file("libv.so", &pf::elf_versioned_library());
        let v = call(&e, "native_library_calls_list", json!({"path": p}));
        let i = &v["result"]["imports"][0];
        assert_eq!((&i["name"], &i["version"], &i["library"]), (&json!("puts"), &json!("GLIBC_2.2.5"), &json!("libc.so.6")));
        let v = call(&e, "native_offered_symbols_list", json!({"path": p}));
        assert_eq!(v["result"]["total"], 2);
        assert_eq!(v["result"]["exports"][0]["version"], "LIB_1.0");
        assert_eq!(v["result"]["exports"][1]["binding"], "weak");

        let p = temp_file("m", &craft_anything_testkit::macho64());
        let v = call(&e, "native_library_calls_list", json!({"path": p}));
        assert!(v["result"]["imports"].as_array().unwrap().iter().any(|i| i["name"].as_str().unwrap().contains("puts")), "{v}");
        assert!(v["result"]["libraries"].as_array().unwrap().iter().any(|l| l["name"].as_str().unwrap().contains("libSystem")), "{v}");
        let _ = call(&e, "native_offered_symbols_list", json!({"path": p}));

        // A file that isn't a program.
        let p = temp_file("t.txt", b"just some words");
        assert!(!call_err(&e, "native_library_calls_list", json!({"path": p})).message.is_empty());
    }

    #[test]
    fn pe_exports_need_no_analysis_and_page() {
        // The active target: no analysis has run, and none does.
        let e = engine_with("facts.dll", &pf::pe_facts());
        let v = call(&e, "native_offered_symbols_list", json!({}));
        let r = &v["result"];
        assert_eq!((&r["total"], &r["forwarded"], &r["ordinal_only"]), (&json!(3), &json!(1), &json!(1)));
        assert_eq!(r["details"]["library_name"], "facts.dll");
        assert_eq!(r["exports"][1]["forwarder"], "NTDLL.RtlBeta");
        assert!(r["exports"][1].get("address").is_none(), "a forwarder holds no code here");
        assert_eq!(r["exports"][2]["ordinal"], 8);
        assert!(r["exports"][2].get("name").is_none_or(Value::is_null));
        assert!(v["summary"].as_str().unwrap().contains("forwarded"));
        let v = call(&e, "native_offered_symbols_list", json!({"contains": "rtlbeta"}));
        assert_eq!(v["result"]["matching"], 1);
        let v = call(&e, "native_offered_symbols_list", json!({"limit": 1, "offset": 1}));
        assert_eq!(v["coverage"]["next_offset"], 2);
    }

    #[test]
    fn signer_says_what_it_checked() {
        let e = engine();
        let p = temp_file("signed.exe", &pf::signed_pe());
        let v = call(&e, "native_publisher_show", json!({"path": p}));
        let s = v["summary"].as_str().unwrap();
        assert!(s.starts_with("Signed by") && s.contains("Craft Signer"), "{s}");
        assert!(s.contains("hash matches") && s.contains("checks out") && s.contains("wasn't checked"), "{s}");
        assert_eq!(v["result"]["signed"], true);
        assert_eq!(v["result"]["file_hash"], "matches");
        assert_eq!(v["result"]["signature_check"]["status"], "valid");
        assert!(v["result"]["signer"]["not_after"].is_string());
        assert!(limitation(&v, "trust_not_checked").is_some());
        assert!(limitation(&v, "attachments_not_read").is_some());
        assert_eq!(v["result"]["table"]["entries"][0]["signature"]["digest_algorithm"], "sha256");

        // Changed after signing.
        let mut tampered = pf::signed_pe();
        let at = craft_anything_formats::pe::headers(&tampered).unwrap().rva_to_offset(0x1000).unwrap();
        tampered[at] ^= 0x55;
        let p = temp_file("tampered.exe", &tampered);
        let v = call(&e, "native_publisher_show", json!({"path": p}));
        assert_eq!(v["result"]["file_hash"], "differs");
        assert!(v["summary"].as_str().unwrap().contains("does NOT match"));

        // Unsigned.
        let p = temp_file("plain.exe", &pf::pe_facts());
        let v = call(&e, "native_publisher_show", json!({"path": p}));
        assert_eq!(v["result"]["has_signature_block"], false);
        assert!(v["summary"].as_str().unwrap().contains("no signature block"));
        assert!(limitation(&v, "catalog_possible").is_some());

        // Not a signature, and not a Windows program.
        let p = temp_file("junk.exe", &pf::pe_with_certificate(&pf::pe_facts(), 2, b"garbage"));
        let v = call(&e, "native_publisher_show", json!({"path": p}));
        assert_eq!(v["result"]["signed"], false);
        assert!(v["summary"].as_str().unwrap().contains("isn't well-formed"));
        let p = temp_file("e", &pf::elf_versioned_library());
        assert!(!call_err(&e, "native_publisher_show", json!({"path": p})).message.is_empty());
    }

    #[test]
    fn model_summaries_are_plain_and_page() {
        let e = engine();
        let d = pf::gguf_header(3);
        let p = temp_file("m.gguf", &d);
        let v = call(&e, "formats_ai_weights_show", json!({"path": p, "limit": 2}));
        let s = v["summary"].as_str().unwrap();
        assert!(s.starts_with("A llama model in GGUF format") && s.contains("thousand parameters") && s.contains("Q4_K"), "{s}");
        assert_eq!(v["result"]["tensors"].as_array().unwrap().len(), 2);
        assert_eq!(v["coverage"]["next_offset"], 2);
        assert!(limitation(&v, "tensor_data_not_read").is_some());
        assert!(v["subject"]["sha256"].is_string(), "the whole file was read");

        let summary = call(&e, "formats_ai_weights_show", json!({"path": p, "detail": "summary"}));
        assert_eq!(summary["result"]["architecture"], "llama");
        assert!(summary["result"]["saved_evidence"]["evidence_id"].is_string());

        let d = pf::safetensors_file(pf::SAFETENSORS_HEADER, 32);
        let p = temp_file("m.safetensors", &d);
        let v = call(&e, "formats_ai_weights_show", json!({"path": p}));
        assert!(v["summary"].as_str().unwrap().contains("safetensors"), "{}", v["summary"]);
        assert_eq!(v["result"]["report"]["parameters"], 14);

        let p = temp_file("bad.safetensors", &pf::safetensors_file("{oops", 0));
        assert!(!call_err(&e, "formats_ai_weights_show", json!({"path": p})).message.is_empty());
        let p = temp_file("no.bin", b"not a model, not even close");
        assert!(!call_err(&e, "formats_ai_weights_show", json!({"path": p})).message.is_empty());
    }

    #[test]
    fn a_model_summary_keeps_every_tensor_for_browsing() {
        let e = engine();
        let mut header = json!({"__metadata__": {"format": "pt"}});
        for i in 0..250 {
            header[format!("t{i:03}.weight")] = json!({"dtype": "F32", "shape": [1], "data_offsets": [i * 4, i * 4 + 4]});
        }
        let p = temp_file("many.safetensors", &pf::safetensors_file(&header.to_string(), 1000));
        let summary = call(&e, "formats_ai_weights_show", json!({"path": p, "detail": "summary"}));
        assert_eq!(summary["result"]["tensors"], 250);
        let source = summary["result"]["saved_evidence"].clone();
        let browse = |offset: usize, limit: usize| {
            call(&e, "core_evidence_browse", json!({"source": source, "show": {"kind": "rows", "list": "tensors", "offset": offset, "limit": limit}}))
        };
        let tail = browse(200, 200);
        assert_eq!(tail["result"]["shown"]["items"].as_array().unwrap().len(), 50);
        assert_eq!(tail["result"]["coverage"]["total"], 250);
        let mut names = Vec::new();
        let mut cursor = 0usize;
        loop {
            let v = browse(cursor, 64);
            names.extend(v["result"]["shown"]["items"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap().to_owned()));
            match v["result"]["coverage"]["next_offset"].as_u64() {
                Some(next) => {
                    assert!(next > cursor as u64);
                    cursor = next as usize;
                }
                None => break,
            }
        }
        assert_eq!(names, (0..250).map(|i| format!("t{i:03}.weight")).collect::<Vec<_>>());
    }

    #[test]
    fn a_big_model_is_read_only_at_its_start() {
        let e = engine();
        // A large file whose tail isn't needed: only the first KiB is read.
        let mut d = pf::gguf_header(3);
        d.resize(4 << 20, 0xee);
        let p = temp_file("big.gguf", &d);
        let v = call(&e, "formats_ai_weights_show", json!({"path": p, "max_header_bytes": 4096}));
        assert_eq!(v["result"]["bytes_read"], 4096);
        assert_eq!(v["result"]["report"]["file_size"], 4 << 20);
        assert!(limitation(&v, "part_of_file_read").is_some());
        assert!(v["subject"].get("sha256").is_none_or(Value::is_null), "a part's hash must not pass for the file's");

        // A limit that ends inside the header says so rather than passing for the whole model.
        let v = call(&e, "formats_ai_weights_show", json!({"path": p, "max_header_bytes": 1024}));
        let cut = pf::gguf_header(3).len() > 1024;
        assert_eq!(v["result"]["report"]["complete"], !cut);

        // Safetensors with a header past the limit: the remedy is named.
        let big = format!("{{\"__metadata__\":{{\"pad\":\"{}\"}}}}", "x".repeat(5000));
        let p = temp_file("h.safetensors", &pf::safetensors_file(&big, 0));
        let err = call_err(&e, "formats_ai_weights_show", json!({"path": p, "max_header_bytes": 1024}));
        assert!(err.remediation.unwrap_or_default().contains("max_header_bytes"));
        assert!(!call_err(&e, "formats_ai_weights_show", json!({"path": p, "max_header_bytes": 1})).message.is_empty());
    }

    /// A first build and a second one with one of everything that can happen to a function.
    fn two_builds() -> (Vec<u8>, Vec<u8>) {
        let left = pf::elf_with_functions(&[
            ("kept", pf::plain_body(1)),
            ("edited", pf::plain_body(2)),
            ("old_name", pf::plain_body(3)),
            ("removed", pf::plain_body(4)),
            ("twin_a", pf::plain_body(7)),
            ("twin_b", pf::plain_body(7)),
        ]);
        let right = pf::elf_with_functions(&[
            ("kept", pf::plain_body(1)),
            ("edited", pf::plain_body(200)),
            ("new_name", pf::plain_body(3)),
            ("added", pf::plain_body(5)),
            ("twin_c", pf::plain_body(7)),
            ("twin_d", pf::plain_body(7)),
        ]);
        (left, right)
    }

    fn pair<'a>(v: &'a Value, left_name: &str) -> &'a Value {
        v["result"]["pairs"].as_array().unwrap().iter().find(|p| p["left"]["name"] == left_name).unwrap_or_else(|| panic!("no pair for {left_name}: {v}"))
    }

    #[test]
    fn matching_renamed_ambiguous_removed_and_changed() {
        let (l, r) = two_builds();
        let (lp, rp) = (temp_file("old.elf", &l), temp_file("new.elf", &r));
        let e = engine();
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": rp}));

        let kept = pair(&v, "kept");
        assert_eq!((&kept["method"], &kept["body"], &kept["confidence"]), (&json!("exact_name"), &json!("identical"), &json!("high")));

        // The same name doesn't mean the same code.
        let edited = pair(&v, "edited");
        assert_eq!((&edited["method"], &edited["body"]), (&json!("exact_name"), &json!("changed")));

        // A new name on the same bytes.
        let renamed = pair(&v, "old_name");
        assert_eq!(
            (&renamed["method"], &renamed["right"]["name"], &renamed["renamed"], &renamed["body"]),
            (&json!("identical_bytes"), &json!("new_name"), &json!(true), &json!("identical"))
        );

        // Twins stay unpaired, on both sides, and aren't guessed.
        let groups = v["result"]["ambiguous"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert_eq!(groups[0]["method"], "identical_bytes");
        let names = |k: &str| groups[0][k].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(names("left"), vec!["twin_a", "twin_b"]);
        assert_eq!(names("right"), vec!["twin_c", "twin_d"]);
        for p in v["result"]["pairs"].as_array().unwrap() {
            assert!(!p["left"]["name"].as_str().unwrap().starts_with("twin"), "{p}");
        }

        // What's on one side only.
        assert_eq!(v["result"]["only_left"].as_array().unwrap().iter().filter(|x| x["name"] == "removed").count(), 1);
        assert_eq!(v["result"]["only_right"].as_array().unwrap().iter().filter(|x| x["name"] == "added").count(), 1);
        assert!(limitation(&v, "same_name_not_same_code").is_some() && limitation(&v, "unpaired_not_removed").is_some());
        assert_eq!(v["result"]["counts"]["changed"], 1);

        // One list at a time, and pages of it.
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": rp, "show": "changed"}));
        assert_eq!(v["result"]["pairs"].as_array().unwrap().len(), 1);
        assert!(v["result"].get("only_left").is_none());
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": rp, "show": "pairs", "limit": 1}));
        assert_eq!(v["coverage"]["status"], "partial");
        assert_eq!(v["coverage"]["next_offset"], 1);
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": rp, "detail": "summary"}));
        assert!(v["result"]["saved_evidence"]["evidence_id"].is_string());
        assert_eq!(v["result"]["counts"]["ambiguous_groups"], 1);
    }

    #[test]
    fn matching_masks_addresses_and_catches_what_masking_hides() {
        // `caller` moves, so its call's offset changes while its instructions don't.
        let callee = pf::plain_body(9);
        let filler = pf::plain_body(8);
        let left = pf::elf_with_functions(&[("callee", callee.clone()), ("", pf::calling_body(0x20, 0, 11))]);
        let right = pf::elf_with_functions(&[("callee", callee.clone()), ("filler", filler), ("", pf::calling_body(0x40, 0, 11))]);
        let (lp, rp) = (temp_file("a.elf", &left), temp_file("b.elf", &right));
        let e = engine();
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": rp}));
        let rows = v["result"]["pairs"].as_array().unwrap();
        let moved = rows.iter().find(|p| p["method"] == "masked_bytes").unwrap_or_else(|| panic!("{v}"));
        assert_eq!(moved["body"], "same_apart_from_addresses", "{moved}");
        assert_eq!(moved["confidence"], "medium");

        // The same bytes apart from where the call goes, but it now reaches another named
        // function: that's changed code.
        let other = pf::plain_body(10);
        let left = pf::elf_with_functions(&[("first", callee.clone()), ("second", other.clone()), ("", pf::calling_body(0x40, 0, 11))]);
        let right = pf::elf_with_functions(&[("first", callee), ("second", other), ("", pf::calling_body(0x40, 0x20, 11))]);
        let (lp, rp) = (temp_file("c.elf", &left), temp_file("d.elf", &right));
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": rp}));
        let moved = v["result"]["pairs"].as_array().unwrap().iter().find(|p| p["method"] == "masked_bytes").unwrap_or_else(|| panic!("{v}"));
        assert_eq!(moved["body"], "changed", "{moved}");
        assert_eq!(moved["differences"], json!(["calls"]));
    }

    #[test]
    fn matching_a_program_with_itself_and_with_bad_input() {
        let (l, _) = two_builds();
        let lp = temp_file("same.elf", &l);
        let e = engine();
        let v = call(&e, "app_builds_line_up", json!({"left": lp, "right": lp}));
        assert_eq!(v["result"]["counts"]["changed"], 0);
        assert!(v["result"]["pairs"].as_array().unwrap().iter().all(|p| p["body"] == "identical"));
        let junk = temp_file("junk", b"this is not a program");
        assert!(!call_err(&e, "app_builds_line_up", json!({"left": lp, "right": junk})).message.is_empty());
        assert!(!call_err(&e, "app_builds_line_up", json!({"left": "relative", "right": lp})).message.is_empty());
        assert!(!call_err(&e, "app_builds_line_up", json!({"left": lp, "right": lp, "max_file_bytes": u64::MAX})).message.is_empty());
    }

    #[test]
    fn tiny_unnamed_bodies_are_counted_not_paired() {
        // Same small body in both builds, unnamed: it says too little, so it isn't paired.
        let tiny = vec![0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let left = pf::elf_with_functions(&[("kept", pf::plain_body(1)), ("", tiny.clone())]);
        let right = pf::elf_with_functions(&[("kept", pf::plain_body(1)), ("", tiny)]);
        let (lp, rp) = (temp_file("t1.elf", &left), temp_file("t2.elf", &right));
        let v = call(&engine(), "app_builds_line_up", json!({"left": lp, "right": rp}));
        assert_eq!(v["result"]["counts"]["pairs"], 1, "{v}");
        assert_eq!(v["result"]["counts"]["only_left_too_small_to_pair"], 1, "{v}");
        assert_eq!(v["result"]["counts"]["only_right_too_small_to_pair"], 1, "{v}");
    }

    #[test]
    fn matching_works_on_arm64_and_says_when_processors_differ() {
        let (arm, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::Aarch64, true);
        let (x64, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let (ap, xp) = (temp_file("arm.elf", &arm), temp_file("x64.elf", &x64));
        let e = engine();
        let v = call(&e, "app_builds_line_up", json!({"left": ap, "right": ap}));
        assert_eq!(v["result"]["left"]["processor"], "arm64");
        assert!(v["result"]["counts"]["pairs"].as_u64().unwrap() >= 2, "{v}");
        assert_eq!(v["result"]["counts"]["changed"], 0);

        // Different processors: names still pair, and no body is called the same or different.
        let v = call(&e, "app_builds_line_up", json!({"left": ap, "right": xp}));
        assert!(limitation(&v, "different_processors").is_some());
        let main = pair(&v, "main");
        assert_eq!((&main["method"], &main["body"]), (&json!("exact_name"), &json!("not_compared")));
        assert_eq!(v["result"]["counts"]["by_method"]["identical_bytes"], 0);
    }

    #[test]
    fn matching_can_be_cancelled() {
        let (l, r) = two_builds();
        let (lp, rp) = (temp_file("x.elf", &l), temp_file("y.elf", &r));
        let e = engine();
        let token = crate::tool::CancelToken::default();
        token.cancel();
        let out = e.call("app_builds_line_up", json!({"left": lp, "right": rp}), CallOptions::new(Caller::Mcp).with_cancel(token));
        assert!(out.is_err());
    }

    #[test]
    fn matching_survives_damaged_builds() {
        let (l, r) = two_builds();
        let rp = temp_file("good.elf", &r);
        let e = engine();
        for (i, m) in craft_anything_testkit::mutations(&l).into_iter().enumerate().take(40) {
            let p = temp_file(&format!("m{i}.elf"), &m);
            let _ = e.call("app_builds_line_up", json!({"left": p, "right": rp}), CallOptions::new(Caller::Mcp));
        }
    }

    fn exported_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().map(|x| x.unwrap().path()).filter(|x| x.extension().is_some_and(|e| e == "c")).collect();
        v.sort();
        v
    }

    fn export_with_limit(e: &Engine, folder: &Path, limit: usize) -> Result<Value, ToolError> {
        let mut session = e.session();
        let mut ctx =
            Ctx { tool: "native_source_folder_write", session: &mut session, cancel: crate::CancelToken::default(), progress: &|_| {}, caller: Caller::Cli };
        source_folder_write_with_limit(&mut ctx, json!({"folder": folder, "unlimited": true}), limit).map(|out| out.to_json())
    }

    #[test]
    fn oversized_export_state_is_refused_without_changing_the_folder() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let folder = tempfile::tempdir().unwrap();
        let state_file = folder.path().join(EXPORT_STATE_FILE);
        let oversized = vec![b' '; 257];
        std::fs::write(&state_file, &oversized).unwrap();
        std::fs::write(folder.path().join("notes.txt"), "keep this").unwrap();
        let error = export_with_limit(&e, folder.path(), 256).unwrap_err();
        assert_eq!(error.code, ErrorCode::OverLimit, "the byte limit is checked before JSON parsing");
        assert_eq!(std::fs::read(&state_file).unwrap(), oversized);
        assert_eq!(std::fs::read_to_string(folder.path().join("notes.txt")).unwrap(), "keep this");
        assert!(exported_files(folder.path()).is_empty());
    }

    #[test]
    fn checkpoint_resource_stops_preserve_outputs_and_resume_state() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let root = tempfile::tempdir().unwrap();
        let reference = root.path().join("reference");
        let full = call(&e, "native_source_folder_write", json!({"folder": reference, "unlimited": true}));
        let all: ExportState = serde_json::from_slice(&std::fs::read(reference.join(EXPORT_STATE_FILE)).unwrap()).unwrap();
        let first_file = full["result"]["written_files"][0].as_str().unwrap();
        let mut one = all.clone();
        one.functions.retain(|_, record| record.file == first_file);
        assert_eq!(one.functions.len(), 1);
        let limit = export_json_size(&one, MAX_EXPORT_STATE_BYTES).unwrap();
        let folder = root.path().join("limited");
        let partial = export_with_limit(&e, &folder, limit).unwrap();
        assert_eq!(partial["result"]["written_now"], 1);
        assert_eq!(partial["result"]["stopped_because"], "state_resource_limit");
        assert_eq!(partial["result"]["finished"], false);
        assert_eq!(partial["coverage"]["status"], "partial");
        assert!(limitation(&partial, "export_state_limit").is_some());
        assert_eq!(exported_files(&folder).len(), 1, "the next output was never written without room for its checkpoint");
        let saved = std::fs::read(folder.join(EXPORT_STATE_FILE)).unwrap();
        let output = std::fs::read(folder.join(first_file)).unwrap();
        assert_eq!(saved.len(), limit);
        assert_eq!(partial["result"]["state_bytes"], limit);
        let resumed = export_with_limit(&e, &folder, limit).unwrap();
        assert_eq!(resumed["result"]["already_done"], 1);
        assert_eq!(resumed["result"]["written_now"], 0);
        assert_eq!(resumed["result"]["stopped_because"], "state_resource_limit");
        assert_eq!(std::fs::read(folder.join(EXPORT_STATE_FILE)).unwrap(), saved);
        assert_eq!(std::fs::read(folder.join(first_file)).unwrap(), output);
        // The writer independently enforces the cap, even if admission were called incorrectly.
        assert_eq!(save_export_state(&folder, &all, limit).unwrap_err().code, ErrorCode::OverLimit);
        assert_eq!(std::fs::read(folder.join(EXPORT_STATE_FILE)).unwrap(), saved);
        assert_eq!(export_with_limit(&e, &folder, limit - 1).unwrap_err().code, ErrorCode::OverLimit);
        assert_eq!(std::fs::read(folder.join(EXPORT_STATE_FILE)).unwrap(), saved);
        let larger = export_json_size(&all, MAX_EXPORT_STATE_BYTES).unwrap();
        let finished = export_with_limit(&e, &folder, larger).unwrap();
        assert_eq!(finished["result"]["finished"], true);
        assert_eq!(finished["result"]["already_done"], 1);
        assert_eq!(exported_files(&folder).len(), all.functions.len());
        assert_eq!(std::fs::read(folder.join(first_file)).unwrap(), output, "resume preserves the previously exported file");
        assert!(std::fs::metadata(folder.join(EXPORT_STATE_FILE)).unwrap().len() <= larger as u64);
    }

    #[test]
    fn checkpoint_byte_accounting_matches_insertions_and_replacements() {
        let mut state = ExportState {
            version: EXPORT_STATE_VERSION,
            target_sha256: "test".into(),
            target_name: "quoted \"target\"\n🦀".into(),
            policy: ExportPolicy::Auto,
            functions: BTreeMap::new(),
        };
        let mut used = export_json_size(&state, 4096).unwrap();
        for (entry, name) in [(1, "one\n\"🦀"), (2, "two\\with\ttabs"), (1, "replacement\u{0}\r\n")] {
            let key = format!("{entry:#x}");
            let record = ExportedFunction {
                file: export_file_name(entry, name),
                name: name.into(),
                lines: 1,
                structured: Some(true),
                engine: "builtin".into(),
                provenance: None,
            };
            let next = export_record_size(&state, used, &key, &record, 4096).unwrap().unwrap();
            assert_eq!(export_record_size(&state, used, &key, &record, next).unwrap(), Some(next));
            assert_eq!(export_record_size(&state, used, &key, &record, next - 1).unwrap(), None);
            state.functions.insert(key, record);
            assert_eq!(export_json_size(&state, 4096).unwrap(), next);
            used = next;
        }
    }

    #[test]
    fn export_state_cannot_claim_reserved_unrelated_or_mismatched_outputs() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let folder = tempfile::tempdir().unwrap();
        call(&e, "native_source_folder_write", json!({"folder": folder.path(), "unlimited": true}));
        let state_file = folder.path().join(EXPORT_STATE_FILE);
        let valid = std::fs::read(&state_file).unwrap();
        let state: ExportState = serde_json::from_slice(&valid).unwrap();
        let (first_entry, first) = state.functions.iter().next().unwrap();
        std::fs::remove_file(folder.path().join(&first.file)).unwrap();
        std::fs::write(folder.path().join("notes.txt"), "not decompiled code").unwrap();
        let preserved: Vec<_> = exported_files(folder.path())
            .into_iter()
            .map(|path| {
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        let second_file = state.functions.values().nth(1).unwrap().file.clone();
        for wrong in [EXPORT_STATE_FILE, "notes.txt", second_file.as_str()] {
            let mut corrupt = state.clone();
            corrupt.functions.get_mut(first_entry).unwrap().file = wrong.into();
            let before = serde_json::to_vec(&corrupt).unwrap();
            std::fs::write(&state_file, &before).unwrap();
            let error = call_err(&e, "native_source_folder_write", json!({"folder": folder.path()}));
            assert!(error.message.contains("recorded output"), "{error:?}");
            assert_eq!(std::fs::read(&state_file).unwrap(), before);
        }
        for wrong_entry in ["not-an-address", "0x0001", "0xfffffffffffffffff"] {
            let mut corrupt = state.clone();
            let record = corrupt.functions.remove(first_entry).unwrap();
            corrupt.functions.insert(wrong_entry.into(), record);
            let before = serde_json::to_vec(&corrupt).unwrap();
            std::fs::write(&state_file, &before).unwrap();
            let error = call_err(&e, "native_source_folder_write", json!({"folder": folder.path()}));
            assert!(error.message.contains("invalid entry address"), "{error:?}");
            assert_eq!(std::fs::read(&state_file).unwrap(), before);
        }
        assert!(!folder.path().join(&first.file).exists());
        assert_eq!(std::fs::read_to_string(folder.path().join("notes.txt")).unwrap(), "not decompiled code");
        for (path, before) in preserved {
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
        std::fs::write(&state_file, valid).unwrap();
        let resumed = call(&e, "native_source_folder_write", json!({"folder": folder.path()}));
        assert_eq!(resumed["result"]["written_now"], 1);
        assert_eq!(resumed["result"]["finished"], true);
    }

    #[test]
    fn export_runs_in_parts_and_does_not_repeat_work() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("out");

        let v = call(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 2}));
        let total = v["result"]["functions_total"].as_u64().unwrap();
        assert!(total > 2, "{v}");
        assert_eq!((&v["result"]["written_now"], &v["result"]["functions_done"], &v["result"]["finished"]), (&json!(2), &json!(2), &json!(false)));
        assert_eq!(v["result"]["stopped_because"], "max_functions");
        assert_eq!(v["result"]["remaining"], total - 2);
        assert!(v["result"]["next_function"].is_string());
        assert_eq!(v["coverage"]["status"], "partial");
        let first_files = exported_files(&folder);
        assert_eq!(first_files.len(), 2);
        let before: Vec<_> = first_files.iter().map(|f| std::fs::metadata(f).unwrap().modified().unwrap()).collect();
        let text = std::fs::read_to_string(&first_files[0]).unwrap();
        assert!(text.starts_with("// "), "{text}");

        // The rest, in a second call: nothing written twice.
        std::thread::sleep(Duration::from_millis(20));
        let v = call(&e, "native_source_folder_write", json!({"folder": folder}));
        assert_eq!(v["result"]["already_done"], 2);
        assert_eq!(v["result"]["written_now"], total - 2);
        assert_eq!(v["result"]["finished"], true);
        assert_eq!(v["result"]["stopped_because"], "finished");
        assert_eq!(v["coverage"]["status"], "complete");
        let after: Vec<_> = first_files.iter().map(|f| std::fs::metadata(f).unwrap().modified().unwrap()).collect();
        assert_eq!(before, after, "finished functions are skipped");
        assert_eq!(exported_files(&folder).len() as u64, total);

        // A third call has nothing to do.
        let v = call(&e, "native_source_folder_write", json!({"folder": folder}));
        assert_eq!((&v["result"]["written_now"], &v["result"]["already_done"]), (&json!(0), &json!(total)));

        // The state file is versioned and says what it's about.
        let state: Value = serde_json::from_slice(&std::fs::read(folder.join(EXPORT_STATE_FILE)).unwrap()).unwrap();
        assert_eq!(state["version"], EXPORT_STATE_VERSION);
        assert_eq!(state["policy"], "auto");
        assert_eq!(state["functions"].as_object().unwrap().len() as u64, total);
        assert_eq!(state["target_sha256"], v["result"]["target_sha256"]);

        // A file that went missing is written again, and only that one.
        std::fs::remove_file(&first_files[0]).unwrap();
        let v = call(&e, "native_source_folder_write", json!({"folder": folder}));
        assert_eq!((&v["result"]["written_now"], &v["result"]["replaced_missing"]), (&json!(1), &json!(1)));
        assert!(first_files[0].is_file());
    }

    #[test]
    fn export_refuses_another_target_and_other_peoples_folders() {
        let (a, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let (b, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::Aarch64, true);
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("out");
        let e = engine_with("a", &a);
        let v = call(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 1}));
        assert_eq!(v["result"]["written_now"], 1);
        let count = exported_files(&folder).len();

        let other = engine_with("b", &b);
        let err = call_err(&other, "native_source_folder_write", json!({"folder": folder}));
        assert!(err.message.contains("different file"), "{}", err.message);
        assert_eq!(exported_files(&folder).len(), count, "nothing was added");

        // A folder with someone's files in it.
        let theirs = tempfile::tempdir().unwrap();
        std::fs::write(theirs.path().join("notes.txt"), b"keep me").unwrap();
        let err = call_err(&e, "native_source_folder_write", json!({"folder": theirs.path()}));
        assert!(err.message.contains("other files"), "{}", err.message);
        assert_eq!(std::fs::read(theirs.path().join("notes.txt")).unwrap(), b"keep me");

        // A state file from the future, or damaged: left alone and refused.
        for bad in [&b"{\"version\":99}"[..], b"not json", b"{}", b"{\"version\":1}"] {
            let dir = tempfile::tempdir().unwrap();
            let state = dir.path().join(EXPORT_STATE_FILE);
            std::fs::write(&state, bad).unwrap();
            let err = call_err(&e, "native_source_folder_write", json!({"folder": dir.path()}));
            assert!(err.message.contains("state file"), "{}", err.message);
            assert_eq!(std::fs::read(&state).unwrap(), bad);
        }

        // Bad parameters and a file in the folder's place.
        assert!(!call_err(&e, "native_source_folder_write", json!({"folder": "relative/path"})).message.is_empty());
        assert!(!call_err(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 0})).message.is_empty());
        assert!(
            call(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 1_000_001, "max_seconds": 3601}))["result"]["finished"]
                .as_bool()
                .unwrap()
        );
        let file = temp_file("a-file", b"x");
        assert!(!call_err(&e, "native_source_folder_write", json!({"folder": file})).message.is_empty());
    }

    #[test]
    fn export_stops_at_its_time_limit_and_when_cancelled() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("out");

        let v = call(&e, "native_source_folder_write", json!({"folder": folder, "max_seconds": 0}));
        assert_eq!((&v["result"]["stopped_because"], &v["result"]["written_now"]), (&json!("time_limit"), &json!(0)));
        assert!(v["result"]["remaining"].as_u64().unwrap() > 0);

        // Cancelled mid-way: refused now, carried on later.
        let token = crate::tool::CancelToken::default();
        token.cancel();
        let out = e.call("native_source_folder_write", json!({"folder": folder}), CallOptions::new(Caller::Mcp).with_cancel(token));
        assert!(out.is_err());
        let v = call(&e, "native_source_folder_write", json!({"folder": folder}));
        assert_eq!(v["result"]["finished"], true);
    }

    #[test]
    fn export_unlimited_is_explicit_and_preserves_legacy_zero_budgets() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("out");
        assert!(call_err(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 0})).message.contains("positive"));
        let limited = call(&e, "native_source_folder_write", json!({"folder": folder, "max_seconds": 0}));
        assert_eq!(limited["result"]["written_now"], 0);
        assert_eq!(limited["result"]["stopped_because"], "time_limit");
        let unlimited = call(&e, "native_source_folder_write", json!({"folder": folder, "max_seconds": 0, "max_functions": 0, "unlimited": true}));
        assert_eq!(unlimited["result"]["finished"], true);
        assert!(unlimited["result"]["written_now"].as_u64().unwrap() > 1);
        assert_eq!(unlimited["result"]["discovery"]["scope"], "discovered_candidates");
        assert!(unlimited["summary"].as_str().unwrap().contains("built-in-discovered candidates"));
    }

    #[test]
    fn an_export_policy_is_stable_and_legacy_exports_keep_the_builtin_engine() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("out");
        call(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 1, "engine": "builtin"}));
        let path = folder.join(EXPORT_STATE_FILE);
        let mut state: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        state["version"] = json!(1);
        state.as_object_mut().unwrap().remove("policy");
        state["engine"] = json!("clean-room lifter");
        for function in state["functions"].as_object_mut().unwrap().values_mut() {
            function.as_object_mut().unwrap().remove("engine");
            function.as_object_mut().unwrap().remove("provenance");
        }
        let legacy = serde_json::to_vec(&state).unwrap();
        std::fs::write(&path, &legacy).unwrap();
        let first_file = exported_files(&folder).remove(0);
        let before = std::fs::read(&first_file).unwrap();
        let err = call_err(&e, "native_source_folder_write", json!({"folder": folder, "engine": "auto"}));
        assert_eq!(err.details.unwrap()["reason"], "export_policy_mismatch");
        assert_eq!(std::fs::read(&path).unwrap(), legacy, "a mismatch never migrates or writes");
        let resumed = call(&e, "native_source_folder_write", json!({"folder": folder}));
        assert_eq!(resumed["result"]["engine_policy"], "builtin");
        assert_eq!(resumed["result"]["already_done"], 1);
        assert_eq!(resumed["result"]["finished"], true);
        assert_eq!(std::fs::read(&first_file).unwrap(), before);
        let migrated: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(migrated["version"], EXPORT_STATE_VERSION);
        assert_eq!(migrated["policy"], "builtin");
        assert!(migrated.get("engine").is_none());
        let records = migrated["functions"].as_object().unwrap();
        assert!(records.values().all(|record| record["engine"] == "clean-room lifter"));
        assert_eq!(records.values().filter(|record| record["provenance"].is_null()).count(), 1, "old provenance is not invented");
    }

    #[test]
    fn missing_outputs_after_the_call_budget_do_not_count_as_done() {
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("out");
        let first = call(&e, "native_source_folder_write", json!({"folder": folder}));
        let files = exported_files(&folder);
        assert!(files.len() > 2);
        std::fs::remove_file(files.first().unwrap()).unwrap();
        std::fs::remove_file(files.last().unwrap()).unwrap();
        let partial = call(&e, "native_source_folder_write", json!({"folder": folder, "max_functions": 1}));
        assert_eq!(partial["result"]["written_now"], 1);
        assert_eq!(partial["result"]["replaced_missing"], 1);
        assert_eq!(partial["result"]["remaining"], 1);
        assert_eq!(partial["result"]["finished"], false);
        assert_eq!(partial["result"]["functions_done"].as_u64().unwrap() + 1, first["result"]["functions_total"].as_u64().unwrap());
        assert!(!files.last().unwrap().is_file());
        assert_eq!(call(&e, "native_source_folder_write", json!({"folder": folder}))["result"]["finished"], true);
    }

    #[test]
    fn export_reports_the_bounded_discovery_scope() {
        use super::super::native_common::NativeState;
        use std::sync::Arc;
        let (bytes, _) = craft_anything_testkit::elf64(craft_anything_testkit::ElfArch::X86_64, true);
        let e = engine_with("prog", &bytes);
        let img = Arc::new(Image::parse(Arc::from(bytes)).unwrap());
        let prog = Program::analyze(&img, &Limits { max_functions: 1, ..Limits::default() }, &craft_anything_disasm::NoControl).unwrap();
        assert!(prog.discovery_capped());
        e.session().active_mut().unwrap().ext.insert(Arc::new(NativeState { img, prog }));
        let folder = tempfile::tempdir().unwrap();
        let result = call(&e, "native_source_folder_write", json!({"folder": folder.path(), "unlimited": true}));
        assert_eq!(result["result"]["finished"], true);
        assert_eq!(result["result"]["discovery"]["capped"], true);
        assert_eq!(result["coverage"]["status"], "partial");
        assert!(limitation(&result, "discovery_capped").is_some());
    }

    #[test]
    fn export_file_names_are_safe_whatever_a_program_calls_things() {
        for name in ["../../etc/passwd", "..\\..\\x", "a/b", "CON", "nul\0", "\u{202e}gnp.exe", "", "...", "名前", &"x".repeat(5000)] {
            let f = export_file_name(0x1234, name);
            assert!(f.starts_with("0000000000001234"), "{f}");
            assert!(f.ends_with(".c"), "{f}");
            assert!(f.len() < 96, "{f}");
            assert!(f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'), "{f}");
            assert_eq!(f.matches('.').count(), 1, "{f}");
        }
        assert!(!comment_safe("a\nsystem(\"x\");\r\u{2028}").contains(['\n', '\r']));
    }
}
