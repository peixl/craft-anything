//! Websites: captured in a private browser, checked by serving the build and comparing
//! screenshots with the original's.

use super::*;
use craft_anything_engine::workspace::route_coverage::{RouteCoverage, RouteResourceLimits};
use craft_anything_engine::workspace::{Claim, PageLikeness};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Read;

pub struct WebsiteKind;

impl WebsiteKind {
    pub const ID: &'static str = "website";
}

/// Where the other pages are listed in the capture folder.
pub const ROUTES_FILE: &str = "routes.json";
/// Where the start page's opened menus, pop-ups and tabs are kept in the capture folder, at the
/// desktop width; [`phone_states_dir`] holds them at the phone width (a menu button often only
/// shows there).
pub const STATES_DIR: &str = "states";

/// The folder for the states opened at a phone `width`: `states-390`.
pub fn phone_states_dir(width: u32) -> String {
    format!("{STATES_DIR}-{width}")
}

/// The phone width among the widths compared (the narrowest under 768 px), if any.
pub fn phone_width(widths: &[u32]) -> Option<u32> {
    widths.iter().copied().filter(|w| *w < 768).min()
}

/// The folders of opened states in a capture folder (`states`, then `states-<width>`).
pub fn state_dirs(capture: &Path) -> Vec<String> {
    let mut dirs: Vec<String> = std::fs::read_dir(capture)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| n == STATES_DIR || n.strip_prefix("states-").is_some_and(|w| w.parse::<u32>().is_ok()))
        .collect();
    dirs.sort();
    dirs
}

/// The opened states the study pictured, as `states/state-<n>.png (label, kind, width)` (none
/// when there were none).
pub fn pictured_states(ws: &Workspace) -> Vec<String> {
    let mut out = Vec::new();
    for dir in state_dirs(&ws.capture_dir()) {
        let Some(v) = read_json(&ws.capture_dir().join(&dir).join("states.json")) else { continue };
        let width = v.get("width").and_then(Value::as_u64).map(|w| format!(", {w} px")).unwrap_or_default();
        out.extend(v.get("states").and_then(Value::as_array).into_iter().flatten().filter_map(|s| {
            let file = s.get("file").and_then(Value::as_str)?;
            let label = s.get("label").and_then(Value::as_str).filter(|l| !l.is_empty()).unwrap_or("a control");
            Some(format!("{dir}/{file} ({label}, {}{width})", s.get("kind").and_then(Value::as_str).unwrap_or("menu")))
        }));
    }
    out
}

/// Another page of the site: its path, the folder name its capture uses, and its address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub path: String,
    pub slug: String,
    pub url: String,
}

fn origin_and_path(url: &str) -> Option<(String, String)> {
    let url = url.split('#').next()?;
    let uri: ureq::http::Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().filter(|p| !((scheme == "http" && *p == 80) || (scheme == "https" && *p == 443)));
    let origin = format!("{scheme}://{host}{}", port.map(|p| format!(":{p}")).unwrap_or_default());
    Some((origin, uri.path().to_string()))
}

pub(crate) fn same_origin(left: &str, right: &str) -> bool {
    matches!((origin_and_path(left), origin_and_path(right)), (Some((a, _)), Some((b, _))) if a == b)
}

fn route_from_link(link: &Value, start: &str) -> Option<Route> {
    let (origin, start_path) = origin_and_path(start)?;
    let (other, path) = origin_and_path(link.get("href")?.as_str()?)?;
    let last = path.rsplit('/').next().unwrap_or_default();
    let file = last.contains('.') && !last.ends_with(".html") && !last.ends_with(".htm");
    if origin != other || file || path.trim_end_matches('/') == start_path.trim_end_matches('/') {
        return None;
    }
    let slug: String = path.trim_matches('/').chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    let slug = slug.split('-').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("-");
    if slug.is_empty() {
        return None;
    }
    let slug = if slug.len() > 96 {
        format!("{}-{}", slug.chars().take(80).collect::<String>(), craft_anything_evidence::sha256_hex(path.as_bytes()).get(..12).unwrap_or_default())
    } else {
        slug
    };
    Some(Route { url: format!("{origin}{path}"), path, slug })
}

/// Up to `max` other pages of the same site, from the links a capture found (`capture.json`'s
/// `links`): same scheme and host, a page rather than a file, each path once, not the start page.
pub fn pick_routes(capture: &Value, start: &str, max: usize) -> Vec<Route> {
    let norm = |p: &str| p.trim_end_matches('/').to_string();
    let mut out: Vec<Route> = Vec::new();
    for link in capture.get("links").and_then(Value::as_array).into_iter().flatten() {
        if out.len() >= max {
            break;
        }
        let Some(route) = route_from_link(link, start) else { continue };
        if !out.iter().any(|r| norm(&r.path) == norm(&route.path) || r.slug == route.slug) {
            out.push(route);
        }
    }
    out
}

/// The next level: up to `max` pages linked from already captured ones (`captures`, their
/// `capture.json`s) that aren't in `have` yet, same rules as [`pick_routes`].
pub fn pick_deeper_routes(captures: &[Value], start: &str, have: &[Route], max: usize) -> Vec<Route> {
    let norm = |p: &str| p.trim_end_matches('/').to_string();
    let mut out: Vec<Route> = Vec::new();
    for c in captures {
        for r in pick_routes(c, start, max.saturating_add(have.len())) {
            if out.len() >= max {
                return out;
            }
            let taken = |x: &Route| norm(&x.path) == norm(&r.path) || x.slug == r.slug;
            if !have.iter().any(taken) && !out.iter().any(taken) {
                out.push(r);
            }
        }
    }
    out
}

/// The other pages captured for a project (none when only the start page was).
pub fn routes(ws: &Workspace) -> Vec<Route> {
    route_list(ws).0
}

/// Read a capture without trusting a file length that might change during the read.
pub(crate) fn read_bounded_json(path: &Path, limit: u64) -> Result<Value, ToolError> {
    let file = std::fs::File::open(path).map_err(|e| ToolError::io(path.display(), e))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes).map_err(|e| ToolError::io(path.display(), e))?;
    if bytes.len() as u64 > limit {
        return Err(ToolError::new(ErrorCode::OverLimit, "The capture JSON exceeds its read budget."));
    }
    serde_json::from_slice(&bytes).map_err(|e| ToolError::invalid(format!("Couldn't read capture JSON: {e}")))
}

fn route_list(ws: &Workspace) -> (Vec<Route>, Option<String>) {
    let path = ws.capture_dir().join(ROUTES_FILE);
    if !path.exists() {
        return (Vec::new(), None);
    }
    let limits = RouteResourceLimits::default();
    let parsed = read_bounded_json(&path, limits.route_manifest_bytes)
        .and_then(|v| serde_json::from_value::<Vec<Route>>(v).map_err(|e| ToolError::invalid(e.to_string())));
    let Ok(mut routes) = parsed else {
        return (Vec::new(), Some("The saved route list could not be read within its bounded format.".into()));
    };
    let mut partial = routes.len() > limits.retained_routes;
    routes.truncate(limits.retained_routes);
    routes.retain(|r| {
        let valid = r.path.len() <= limits.url_bytes
            && r.url.len() <= limits.url_bytes
            && r.path.starts_with('/')
            && !r.slug.is_empty()
            && r.slug.len() <= 128
            && r.slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        partial |= !valid;
        valid
    });
    (routes, partial.then(|| "The saved route list exceeds its count or path bounds; only the valid retained prefix was used.".into()))
}

pub(crate) fn route_coverage(ws: &Workspace) -> Option<RouteCoverage> {
    read_bounded_json(&ws.capture_dir().join(craft_anything_engine::workspace::route_coverage::FILE), 64 * 1024)
        .ok()
        .and_then(|v| RouteCoverage::from_value(v).ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAction {
    Open,
    Capture,
}

struct RouteQueue {
    pending: VecDeque<(Route, usize)>,
    seen: HashSet<String>,
    slugs: HashSet<String>,
    report: RouteCoverage,
}

impl RouteQueue {
    fn discover(&mut self, capture: &Value, start: &str, depth: usize) {
        let limits = &self.report.resource_limits;
        let links = capture.get("links").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        if links.len() > limits.links_per_page {
            self.report.boundary("links_per_page");
        }
        let limits = self.report.resource_limits.clone();
        for link in links.iter().take(limits.links_per_page) {
            if link.get("href").and_then(Value::as_str).is_some_and(|u| u.len() > limits.url_bytes) {
                self.report.boundary("url_bytes");
                continue;
            }
            let Some(mut route) = route_from_link(link, start) else { continue };
            let key = route.url.trim_end_matches('/').to_string();
            if self.seen.contains(&key) {
                continue;
            }
            if self.report.max_depth.is_some_and(|max| depth > max) {
                self.report.boundary("depth_limit");
                break;
            }
            if self.seen.len() >= limits.visited_routes {
                self.report.boundary("visited_routes");
                break;
            }
            self.seen.insert(key);
            self.report.discovered = self.seen.len();
            if self.pending.len() >= limits.frontier_routes {
                self.report.boundary("frontier_routes");
                break;
            }
            if !self.slugs.insert(route.slug.clone()) {
                route.slug = format!("{}-{}", route.slug, craft_anything_evidence::sha256_hex(route.path.as_bytes()).get(..12).unwrap_or_default());
                if !self.slugs.insert(route.slug.clone()) {
                    self.report.boundary("slug_collision");
                    continue;
                }
            }
            self.pending.push_back((route, depth));
        }
    }
}

fn save_route_capture(capture: &Path, routes: &[Route], report: &RouteCoverage) -> Result<(), ToolError> {
    std::fs::create_dir_all(capture).map_err(|e| ToolError::io(capture.display(), e))?;
    let save = |name: &str, value: &Value| {
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| ToolError::internal(e.to_string()))?;
        craft_anything_engine::project::write_atomic(&capture.join(name), &bytes)
    };
    save(ROUTES_FILE, &json!(routes))?;
    save(craft_anything_engine::workspace::route_coverage::FILE, &json!(report))
}

/// Breadth-first study. Navigation and capture are separate so a cross-origin redirect is
/// rejected before any screenshot/source capture. The callback makes this path testable without a browser.
pub(crate) fn capture_routes_with(
    capture_directory: &Path,
    start: &str,
    initial: &Value,
    settings: &craft_anything_engine::settings::BuildSettings,
    stop: &CancelToken,
    mut visit: impl FnMut(RouteAction, &Route) -> Result<Value, ToolError>,
) -> Result<RouteCoverage, ToolError> {
    let report = RouteCoverage {
        max_pages: (!settings.unlimited_pages).then_some(settings.max_pages),
        max_depth: (settings.max_page_depth != 0).then_some(settings.max_page_depth),
        ..RouteCoverage::default()
    };
    let mut queue = RouteQueue { pending: VecDeque::new(), seen: HashSet::new(), slugs: HashSet::new(), report };
    queue.discover(initial, start, 1);
    let mut kept = Vec::new();
    let outcome = loop {
        if stop.is_cancelled() {
            queue.report.boundary("cancelled");
            break Err(ToolError::cancelled());
        }
        if !queue.pending.is_empty() && queue.report.max_pages.is_some_and(|max| kept.len() >= max) {
            queue.report.boundary("count_limit");
            break Ok(());
        }
        if !queue.pending.is_empty() && kept.len() >= queue.report.resource_limits.retained_routes {
            queue.report.boundary("retained_routes");
            break Ok(());
        }
        let Some((route, depth)) = queue.pending.pop_front() else {
            break Ok(());
        };
        queue.report.attempted =
            queue.report.attempted.checked_add(1).ok_or_else(|| ToolError::new(ErrorCode::OverLimit, "Route attempt counter overflow."))?;
        let visited = visit(RouteAction::Open, &route).and_then(|opened| {
            let final_url = opened.get("url").and_then(Value::as_str).ok_or_else(|| ToolError::invalid("Navigation did not report its final URL."))?;
            if !same_origin(start, final_url) {
                return Ok(None);
            }
            stop.check()?;
            visit(RouteAction::Capture, &route).map(Some)
        });
        match visited {
            Ok(Some(capture)) => {
                let Some(captured_url) = capture.get("url").and_then(Value::as_str) else {
                    queue.report.failed = queue.report.failed.saturating_add(1);
                    queue.report.boundary("capture_url_missing");
                    save_route_capture(capture_directory, &kept, &queue.report)?;
                    continue;
                };
                if !same_origin(start, captured_url) {
                    queue.report.redirected_outside_origin = queue.report.redirected_outside_origin.saturating_add(1);
                    queue.report.boundary("capture_redirected_outside_origin");
                    save_route_capture(capture_directory, &kept, &queue.report)?;
                    continue;
                }
                kept.push(route);
                queue.report.captured = kept.len();
                if let Some(next) = depth.checked_add(1) {
                    queue.discover(&capture, start, next);
                } else {
                    queue.report.boundary("depth_counter");
                }
            }
            Ok(None) => {
                queue.report.redirected_outside_origin = queue.report.redirected_outside_origin.saturating_add(1);
                queue.report.boundary("redirected_outside_origin");
            }
            Err(e) if e.code == ErrorCode::Cancelled => {
                queue.report.boundary("cancelled");
                break Err(e);
            }
            Err(e) => {
                queue.report.failed = queue.report.failed.saturating_add(1);
                queue.report.boundary(if e.code == ErrorCode::OverLimit { "capture_json_bytes" } else { "capture_failed" });
            }
        }
        save_route_capture(capture_directory, &kept, &queue.report)?;
    };
    save_route_capture(capture_directory, &kept, &queue.report)?;
    outcome.map(|()| queue.report)
}

impl TargetKind for WebsiteKind {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn words(&self) -> KindWords {
        KindWords {
            button: "Open the website",
            icon: "external-link",
            ready: "Your website is ready",
            change_hint: "Ask for a change, e.g. \"make the header blue\" or \"add a contact form\"",
        }
    }

    /// A website wins when the target already is one, the request names one, or the chosen stack
    /// builds sites. The generic word "web" is not enough: "a web app" is an app.
    fn detect(&self, cx: &DetectCx) -> Option<u32> {
        if matches!(cx.target, TargetRef::Website { .. }) {
            Some(100)
        } else if cx.says(&[
            " website",
            " web page",
            " webpage",
            " landing page",
            " site ",
            " webseite",
            " internetseite",
            " sitio web",
            " página web",
            " pagina web",
            " sito ",
            " web sitesi",
            " internet sitesi",
            " trang web",
            "เว็บไซต์",
            "หน้าเว็บ",
            "网站",
            "網站",
            "网页",
            "網頁",
        ]) || says_site_in_estonian(cx)
        {
            Some(50)
        } else if matches!(cx.target, TargetRef::None) && stacks::get(cx.stack).is_some_and(|s| s.site) {
            // Built as a site with nothing to recreate: "add a contact form" never says website.
            Some(30)
        } else {
            None
        }
    }

    /// A stack the request doesn't name is the builder's to choose, matching the original's.
    fn default_stack(&self, _cx: &DetectCx) -> &'static str {
        stacks::BUILDERS_CHOICE
    }

    fn goal(&self) -> &'static str {
        "a website that looks and behaves like the original"
    }

    fn self_screenshots(&self) -> bool {
        false
    }

    fn brief_sections(&self, cx: &BriefCx) -> Vec<String> {
        let mut out = Vec::new();
        let (routes, warning) = route_list(cx.ws);
        if !routes.is_empty() {
            let shown = RouteResourceLimits::default().prompt_routes;
            let list = routes.iter().take(shown).map(|r| format!("{} (capture/routes/{}/)", short_note(&r.path, 160), r.slug)).collect::<Vec<_>>().join(", ");
            out.push(format!(
                "The site has more pages, captured the same way: {list}. Rebuild each at the same path, with the same navigation between them; they're compared with the original too."
            ));
            if routes.len() > shown {
                out.push(format!("This brief lists the first {shown} of {} captured routes. Read capture/routes.json for every exact path and capture folder; the remaining routes are part of the build and checks too.", routes.len()));
            }
        }
        if let Some(warning) = warning {
            out.push(warning);
        }
        if let Some(coverage) = route_coverage(cx.ws) {
            out.push(route_scope_note(&coverage));
        }
        let states = pictured_states(cx.ws);
        if !states.is_empty() {
            out.push(format!(
                "Its menus, pop-ups and tabs were opened one at a time and photographed in capture/ (on a computer, and on a phone where its controls differ, such as a menu button): {}. Make them open and look the same way at each width.",
                states.join(", ")
            ));
        }
        out
    }

    fn checks(&self, ws: &Workspace) -> Vec<Box<dyn Check>> {
        // A site made from a request alone has nothing to compare with: it must build.
        if matches!(ws.manifest.target, TargetRef::Website { .. }) { vec![Box::new(WebVisualCheck)] } else { vec![Box::new(BuildCheck)] }
    }

    fn refine(&self, check: &CheckResult, sees_pictures: bool) -> String {
        match check.similarity {
            Some(s) if sees_pictures => format!(
                "Check {}: compared with the original, your build looks {s:.0}% alike ({}). Your screenshots are in checks/round-{}/ (screenshot-<width>.png for each width, and routes/<page>/ for other pages) with the layout measured at each width in its capture.json; the original's are in capture/. Open each pair with the Read tool, fix the biggest visible differences first (layout and section order, spacing, sizes, colours, fonts, missing parts), fix the padding, items per row, sizes, colours and fonts the check names at each width with the exact values it gives, add any missing headings or words it lists, build it again, and reply with 1-2 plain sentences on what you changed.",
                check.round, check.note, check.round
            ),
            // The likeness is measured from the screenshots, but the same measurements are in
            // text: the build's capture.json beside the original's.
            Some(s) => format!(
                "Check {}: compared with the original, your build looks {s:.0}% alike ({}). The check measured your build at each width the same way as the original: compare checks/round-{}/capture.json (and routes/<page>/capture.json for other pages) with capture/capture.json, fix the layout and section order and anything missing first, then the padding, items per row, sizes, colours and fonts the check names at each width with the exact values it gives, add any missing headings or words it lists, build it again, and reply with 1-2 plain sentences on what you changed.",
                check.round, check.note, check.round
            ),
            None => format!(
                "Check {}: {}\n\nFix this in app/, build again until it succeeds, and reply with 1-2 plain sentences on what you changed.",
                check.round, check.note
            ),
        }
    }
}

/// How alike two captures' visible text is (`capture.json`'s `text` and `headings`).
#[derive(Debug, Clone, PartialEq)]
pub struct TextLikeness {
    /// Word overlap, 0..=100 (Dice over word counts).
    pub similarity: f64,
    /// The original's headings the build doesn't have, in page order (at most 8).
    pub missing_headings: Vec<String>,
    /// The original's most frequent words the build never uses (at most 12).
    pub missing_words: Vec<String>,
}

pub(crate) fn words(text: &str) -> std::collections::BTreeMap<String, usize> {
    let mut m = std::collections::BTreeMap::new();
    for w in text.split(|c: char| !c.is_alphanumeric()).filter(|w| w.chars().count() >= 2) {
        *m.entry(w.to_lowercase()).or_insert(0) += 1;
    }
    m
}

/// Compare the visible text of the original's capture with the build's. None when the original
/// has no text to compare.
pub fn text_likeness(original: &Value, built: &Value) -> Option<TextLikeness> {
    let text = |v: &Value| v.get("text").and_then(Value::as_str).unwrap_or_default().to_string();
    let (a, b) = (words(&text(original)), words(&text(built)));
    let total_a: usize = a.values().sum();
    if total_a == 0 {
        return None;
    }
    let total_b: usize = b.values().sum();
    let shared: usize = a.iter().map(|(w, n)| (*n).min(b.get(w).copied().unwrap_or(0))).sum();
    let similarity = 200.0 * shared as f64 / (total_a + total_b) as f64;
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let built_headings: std::collections::BTreeSet<String> =
        built.get("headings").and_then(Value::as_array).into_iter().flatten().filter_map(|h| h.get("text").and_then(Value::as_str)).map(norm).collect();
    let missing_headings = original
        .get("headings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|h| h.get("text").and_then(Value::as_str))
        .filter(|h| !h.trim().is_empty() && !built_headings.contains(&norm(h)))
        .take(8)
        .map(|h| h.trim().to_string())
        .collect();
    let mut missing: Vec<(&String, &usize)> = a.iter().filter(|(w, _)| !b.contains_key(*w)).collect();
    missing.sort_by(|x, y| y.1.cmp(x.1).then_with(|| x.0.cmp(y.0)));
    let missing_words = missing.into_iter().take(12).map(|(w, _)| w.clone()).collect();
    Some(TextLikeness { similarity, missing_headings, missing_words })
}

impl TextLikeness {
    /// One line for the check's note, e.g. `text 72% alike; missing headings: "Pricing"; missing words: faq, plans`.
    pub fn note(&self) -> String {
        let mut s = format!("text {:.0}% alike", self.similarity);
        if !self.missing_headings.is_empty() {
            s.push_str(&format!("; missing headings: {}", self.missing_headings.iter().map(|h| format!("\"{h}\"")).collect::<Vec<_>>().join(", ")));
        }
        if !self.missing_words.is_empty() {
            s.push_str(&format!("; missing words: {}", self.missing_words.join(", ")));
        }
        s
    }
}

/// The parts of a page the structure is compared by, as (element, plain name). Elements with
/// the same name count as one part (`ul` and `ol` are both a list).
const PARTS: &[(&str, &str)] = &[
    ("header", "header"),
    ("nav", "navigation bar"),
    ("main", "main area"),
    ("footer", "footer"),
    ("section", "section"),
    ("article", "article"),
    ("aside", "sidebar"),
    ("form", "form"),
    ("h1", "top heading"),
    ("h2", "subheading"),
    ("h3", "subheading"),
    ("h4", "subheading"),
    ("ul", "list"),
    ("ol", "list"),
    ("img", "image"),
    ("video", "video"),
    ("button", "button"),
    ("input", "form field"),
    ("select", "form field"),
    ("textarea", "form field"),
];

/// The page's parts in document order, from `capture.json`'s outline (a role counts as its element).
fn skeleton(capture: &Value) -> Vec<&'static str> {
    capture
        .get("outline")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let tag = match item.get("role").and_then(Value::as_str) {
                Some("banner") => "header",
                Some("navigation") => "nav",
                Some("main") => "main",
                Some("contentinfo") => "footer",
                Some("complementary") => "aside",
                Some("form" | "search") => "form",
                Some("button") => "button",
                Some("img") => "img",
                _ => item.get("tag").and_then(Value::as_str)?,
            };
            PARTS.iter().find(|(t, _)| *t == tag).map(|(_, name)| *name)
        })
        .collect()
}

/// Length of the longest sequence both have in the same order.
fn common_len(a: &[&str], b: &[&str]) -> usize {
    let mut row = vec![0usize; b.len() + 1];
    for x in a {
        let mut diag = 0;
        for (j, y) in b.iter().enumerate() {
            let up = row[j + 1];
            row[j + 1] = if x == y { diag + 1 } else { up.max(row[j]) };
            diag = up;
        }
    }
    row[b.len()]
}

/// How alike two captures' page structure is: their landmarks, headings, lists, media and
/// controls, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct StructureLikeness {
    /// 0..=100: the parts both have in the same order, over all parts of both.
    pub similarity: f64,
    /// Parts the original has more of, as (plain name, how many more), most first (at most 6).
    pub missing: Vec<(&'static str, usize)>,
}

/// Compare the original's page structure with the build's. None when the original's outline has
/// none of the parts.
pub fn structure_likeness(original: &Value, built: &Value) -> Option<StructureLikeness> {
    let (a, b) = (skeleton(original), skeleton(built));
    if a.is_empty() {
        return None;
    }
    let similarity = 200.0 * common_len(&a, &b) as f64 / (a.len() + b.len()) as f64;
    let count = |s: &[&str], name: &str| s.iter().filter(|p| **p == name).count();
    let mut missing: Vec<(&'static str, usize)> = Vec::new();
    for (_, name) in PARTS {
        if !missing.iter().any(|(n, _)| n == name) {
            let more = count(&a, name).saturating_sub(count(&b, name));
            if more > 0 {
                missing.push((name, more));
            }
        }
    }
    missing.sort_by_key(|m| std::cmp::Reverse(m.1));
    missing.truncate(6);
    Some(StructureLikeness { similarity, missing })
}

impl StructureLikeness {
    /// One line for the check's note, e.g. `structure 80% alike; missing parts: 2 lists, a form`.
    pub fn note(&self) -> String {
        let mut s = format!("structure {:.0}% alike", self.similarity);
        if !self.missing.is_empty() {
            let parts = self.missing.iter().map(|(name, n)| if *n == 1 { format!("a {name}") } else { format!("{n} {name}s") }).collect::<Vec<_>>();
            s.push_str(&format!("; missing parts: {}", parts.join(", ")));
        }
        s
    }
}

/// What the build gets wrong that the original doesn't, from both captures' `health` and `a11y`:
/// script and console errors, requests that fail (compared by path, since the build is served
/// from elsewhere), and controls without a name, pictures without alt text or a missing page
/// language. Problems the original has too aren't the build's to fix.
pub fn health_notes(original: &Value, built: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let new_errors = new_errors(original, built);
    if !new_errors.is_empty() {
        let shown: Vec<String> = new_errors.iter().take(3).map(|t| format!("\"{t}\"")).collect();
        out.push(format!("the build logs {} error(s) the original doesn't: {}", new_errors.len(), shown.join("; ")));
    }
    let failing = new_failures(original, built);
    if !failing.is_empty() {
        out.push(format!("{} request(s) fail in the build: {}", failing.len(), failing.iter().take(5).cloned().collect::<Vec<_>>().join(", ")));
    }
    let n = |v: &Value, k: &str| v.pointer(&format!("/a11y/{k}")).and_then(Value::as_u64).unwrap_or(0);
    if built.get("a11y").is_some() {
        for (k, what) in [("unnamed_controls", "controls without a name"), ("images_without_alt", "pictures without alt text")] {
            if n(built, k) > n(original, k) {
                out.push(format!("{} {what} (the original has {})", n(built, k), n(original, k)));
            }
        }
        let lang = |v: &Value| v.pointer("/a11y/lang").and_then(Value::as_str).unwrap_or_default().to_string();
        if lang(built).is_empty() && !lang(original).is_empty() {
            out.push(format!("the page language isn't set (the original's is {})", lang(original)));
        }
    }
    out
}

fn health_list(v: &Value, p: &str) -> Vec<Value> {
    v.pointer(p).and_then(Value::as_array).cloned().unwrap_or_default()
}

/// The build's error texts the original doesn't log.
fn new_errors(original: &Value, built: &Value) -> Vec<String> {
    let text = |e: &Value| e.get("text").and_then(Value::as_str).unwrap_or_default().to_string();
    let theirs: Vec<String> = health_list(original, "/health/errors").iter().map(text).collect();
    health_list(built, "/health/errors").iter().map(text).filter(|t| !t.is_empty() && !theirs.contains(t)).collect()
}

/// The build's failing requests the original doesn't have, by path, as `/logo.png (404)`.
fn new_failures(original: &Value, built: &Value) -> Vec<String> {
    let path = |f: &Value| {
        let url = f.get("url").and_then(Value::as_str).unwrap_or_default();
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        rest.find('/').map_or("/".to_string(), |i| rest.get(i..).unwrap_or("/").to_string())
    };
    let theirs: Vec<String> = health_list(original, "/health/failed_requests").iter().map(path).collect();
    health_list(built, "/health/failed_requests")
        .iter()
        .filter(|f| !theirs.contains(&path(f)))
        .map(|f| {
            let why = f
                .get("status")
                .and_then(Value::as_u64)
                .map(|s| s.to_string())
                .or_else(|| f.get("error").and_then(Value::as_str).map(String::from))
                .unwrap_or_default();
            format!("{} ({why})", path(f))
        })
        .collect()
}

/// What `page` of the build must do, each judged on its own from the two captures: not scroll
/// sideways at any width where the original doesn't, log no errors and fail no requests the
/// original doesn't, and have the original's landmarks. A claim is made only when both captures
/// hold what it needs (older captures make none).
pub fn page_claims(page: &str, original: &Value, built: &Value) -> Vec<Claim> {
    let mut out = Vec::new();
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let built_layouts = built.get("layouts").and_then(Value::as_array).cloned().unwrap_or_default();
    for theirs in original.get("layouts").and_then(Value::as_array).into_iter().flatten() {
        let w = n(theirs, "width");
        if n(theirs, "page_w") > w + 1 {
            continue;
        }
        if let Some(ours) = built_layouts.iter().find(|l| n(l, "width") == w) {
            let pw = n(ours, "page_w");
            out.push(Claim::new(format!("{page} doesn't scroll sideways at {w} px"), pw <= w + 1, format!("it's {pw} px wide")));
        }
    }
    if original.get("health").is_some() && built.get("health").is_some() {
        let errors = new_errors(original, built);
        out.push(Claim::new(format!("{page} logs no errors the original doesn't"), errors.is_empty(), errors.first().cloned().unwrap_or_default()));
        let failing = new_failures(original, built);
        out.push(Claim::new(
            format!("{page} loads every file it asks for"),
            failing.is_empty(),
            failing.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
        ));
    }
    let landmarks =
        |v: &Value| -> Vec<String> { v.pointer("/a11y/landmarks").and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default() };
    if built.get("a11y").is_some() && !landmarks(original).is_empty() {
        let ours = landmarks(built);
        let missing: Vec<String> = landmarks(original).into_iter().filter(|l| !ours.contains(l)).collect();
        out.push(Claim::new(format!("{page} has the original's landmarks"), missing.is_empty(), format!("missing: {}", missing.join(", "))));
    }
    out
}

/// A `#rrggbb` or `#rrggbbaa` colour as (r, g, b, a).
fn rgba(c: &str) -> Option<[u8; 4]> {
    let h = c.strip_prefix('#')?;
    let byte = |i: usize| h.get(i..i + 2).and_then(|x| u8::from_str_radix(x, 16).ok());
    match h.len() {
        6 => Some([byte(0)?, byte(2)?, byte(4)?, 255]),
        8 => Some([byte(0)?, byte(2)?, byte(4)?, byte(6)?]),
        _ => None,
    }
}

/// Whether the request names a website in Estonian. `DetectCx::words` turns punctuation and
/// newlines into spaces, so a cue after them still counts.
fn says_site_in_estonian(cx: &DetectCx) -> bool {
    cx.words.split_whitespace().any(is_site_word)
}

/// The same colour to the eye: each channel within 3 (rounding in the browser), or the same text.
fn same_colour(a: &str, b: &str) -> bool {
    match (rgba(a), rgba(b)) {
        (Some(x), Some(y)) => x.iter().zip(y).all(|(p, q)| p.abs_diff(q) <= 3),
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// The first family of a CSS font stack, as a person names it: `"__Figtree_a1b2c3", sans-serif`
/// (how next/font renames a font) reads `Figtree`.
fn family(stack: &str) -> String {
    let first = stack.split(',').next().unwrap_or_default().trim().trim_matches(['"', '\'']);
    first.trim_start_matches('_').split('_').next().unwrap_or(first).to_string()
}

/// The values of a `design` list (`[{value, count}]`), most used first.
fn design_values<'a>(capture: &'a Value, key: &str) -> Vec<&'a str> {
    capture.pointer(&format!("/design/{key}")).and_then(Value::as_array).into_iter().flatten().filter_map(|x| x.get("value").and_then(Value::as_str)).collect()
}

/// What a person sees differ between the original's capture and the build's, for the builder:
/// colours, the main font, text sizes and spacing the build doesn't use, and at each width a
/// page that scrolls sideways, heading sizes, and sections whose padding, items per row or
/// content column differ (sections are paired by tag and heading, in order). Both are
/// `capture.json` documents; empty when nothing differs or there's nothing to compare.
pub fn design_notes(original: &Value, built: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut colours = Vec::new();
    for (key, what) in [("backgrounds", "background"), ("text_colors", "text")] {
        let ours = design_values(built, key);
        colours.extend(design_values(original, key).into_iter().take(6).filter(|c| !ours.iter().any(|o| same_colour(c, o))).map(|c| format!("{c} ({what})")));
    }
    if !colours.is_empty() {
        out.push(format!("colours the original uses that the build doesn't: {}", colours.join(", ")));
    }
    if let (Some(a), Some(b)) = (design_values(original, "fonts").first(), design_values(built, "fonts").first())
        && !family(a).eq_ignore_ascii_case(&family(b))
    {
        out.push(format!("main font: {} in the original, {} in the build", family(a), family(b)));
    }
    for (key, what) in [("font_sizes", "text sizes"), ("spacing", "spacing")] {
        let ours = design_values(built, key);
        let missing: Vec<&str> = design_values(original, key).into_iter().take(8).filter(|v| !ours.contains(v)).collect();
        if !missing.is_empty() {
            out.push(format!("{what} the original uses that the build doesn't: {}", missing.join(", ")));
        }
    }
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let layouts = |v: &Value| v.get("layouts").and_then(Value::as_array).cloned().unwrap_or_default();
    let built_layouts = layouts(built);
    for theirs in layouts(original) {
        let w = n(&theirs, "width");
        let Some(ours) = built_layouts.iter().find(|l| n(l, "width") == w) else { continue };
        let mut diffs = Vec::new();
        if n(ours, "page_w") > w + 1 && n(&theirs, "page_w") <= w + 1 {
            diffs.push(format!("the page scrolls sideways ({} px wide)", n(ours, "page_w")));
        }
        for (k, name) in [("h1", "top heading"), ("h2", "subheadings"), ("body", "body text")] {
            let size = |l: &Value| l.pointer(&format!("/type/{k}")).and_then(Value::as_u64).unwrap_or(0);
            let (a, b) = (size(&theirs), size(ours));
            if a > 0 && b > 0 && a.abs_diff(b) > 2 {
                diffs.push(format!("{name} {b} px, the original's {a} px"));
            }
        }
        diffs.extend(block_diffs(&theirs, ours).into_iter().take(4));
        if !diffs.is_empty() {
            out.push(format!("at {w} px: {}", diffs.join("; ")));
        }
    }
    out
}

/// The sections of one width whose padding, items per row or content column differ. Sections are
/// paired first by tag and heading in order (the n-th `section "Plans"` with the n-th), then,
/// because the builder writes its own words, the rest of each tag in page order (the original's
/// "Why people switch" with the build's "Why people like it"). Items per row is a grid's measure,
/// so it isn't compared for a `nav` or `header` (a row of links, checked by the pictures).
fn block_diffs(original: &Value, built: &Value) -> Vec<String> {
    let blocks = |v: &Value| v.get("blocks").and_then(Value::as_array).cloned().unwrap_or_default();
    let key = |b: &Value| {
        let heading = b.get("heading").and_then(Value::as_str).unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        (b.get("tag").and_then(Value::as_str).unwrap_or_default().to_string(), heading)
    };
    let nums = |b: &Value, k: &str| -> Vec<u64> { b.get(k).and_then(Value::as_array).into_iter().flatten().map(|x| x.as_u64().unwrap_or(0)).collect() };
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let column = |b: &Value, k: &str| b.get("column").map(|c| n(c, k));
    let (theirs, ours) = (blocks(original), blocks(built));
    // The build's block paired with each of the original's, if any.
    let mut partner: Vec<Option<usize>> = vec![None; theirs.len()];
    let mut taken = vec![false; ours.len()];
    let mut pair = |same: &dyn Fn(&Value, &Value) -> bool, partner: &mut Vec<Option<usize>>| {
        for (i, a) in theirs.iter().enumerate() {
            if partner[i].is_some() {
                continue;
            }
            if let Some(j) = ours.iter().enumerate().position(|(j, b)| !taken[j] && same(a, b)) {
                taken[j] = true;
                partner[i] = Some(j);
            }
        }
    };
    pair(&|a, b| key(a) == key(b), &mut partner);
    pair(&|a, b| key(a).0 == key(b).0, &mut partner);
    let mut out = Vec::new();
    for (i, a) in theirs.iter().enumerate() {
        let k = key(a);
        let Some(b) = partner[i].and_then(|j| ours.get(j)) else { continue };
        let mut what = Vec::new();
        let (pa, pb) = (nums(a, "pad"), nums(b, "pad"));
        if pa.len() == pb.len() && pa.iter().zip(&pb).any(|(x, y)| x.abs_diff(*y) > 4) {
            let show = |p: &[u64]| p.iter().map(u64::to_string).collect::<Vec<_>>().join(" ");
            what.push(format!("padding {} vs the original's {}", show(&pb), show(&pa)));
        }
        let grid = !matches!(k.0.as_str(), "nav" | "header");
        if grid && n(a, "per_row") != n(b, "per_row") {
            what.push(format!("{} per row vs {}", n(b, "per_row"), n(a, "per_row")));
        }
        if let (Some(x), Some(y)) = (column(a, "max_w"), column(b, "max_w"))
            && x.abs_diff(y) > 8
        {
            what.push(format!("content column {y} px vs {x} px"));
        } else if column(a, "max_w").is_some() && column(b, "max_w").is_none() {
            what.push(format!("no content column (the original's is {} px)", column(a, "max_w").unwrap_or(0)));
        }
        if !what.is_empty() {
            let name = if k.1.is_empty() {
                format!("the {}", k.0)
            } else {
                format!("the \"{}\" {}", a.get("heading").and_then(Value::as_str).unwrap_or_default(), k.0)
            };
            out.push(format!("{name}: {}", what.join(", ")));
        }
    }
    out
}

/// Pair each state the study pictured with the build's: the same kind of control with the same
/// label, ignoring case and spacing. The build's half is None when it has no such control or
/// couldn't picture it. Both are `states.json` documents.
pub fn pair_states<'a>(original: &'a Value, built: &'a Value) -> Vec<(&'a Value, Option<&'a Value>)> {
    let rows = |v: &'a Value| v.get("states").and_then(Value::as_array).into_iter().flatten().filter(|s| s.get("file").is_some());
    let key = |s: &Value| {
        let label = s.get("label").and_then(Value::as_str).unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        (s.get("kind").and_then(Value::as_str).unwrap_or_default().to_string(), label)
    };
    rows(original).map(|o| (o, rows(built).find(|b| key(b) == key(o)))).collect()
}

/// Read a JSON file, or None.
fn read_json(path: &Path) -> Option<Value> {
    read_bounded_json(path, RouteResourceLimits::default().capture_json_bytes).ok()
}

fn short_note(text: &str, chars: usize) -> String {
    let mut iter = text.chars();
    let mut shown: String = iter.by_ref().take(chars).collect();
    if iter.next().is_some() {
        shown.push_str("… (see the page's capture/check files)");
    }
    shown
}

fn route_scope_note(coverage: &RouteCoverage) -> String {
    format!(
        "Route-study scope: {} captured from {} attempted additional pages; boundaries: {}. The configured count/depth and resource bounds are recorded in capture/routes-coverage.json.",
        coverage.captured,
        coverage.attempted,
        if coverage.boundaries.is_empty() { "none in the discovered queue".into() } else { coverage.boundaries.join(", ") }
    )
}

/// A picture of the build against the original's, in percent: (likeness, layout, detail), then
/// the two heights in px.
type Likeness = (f64, f64, f64, u64, u64);

/// Compare the build's picture with the original's. None when either picture is missing or they
/// couldn't be compared.
fn picture_likeness(cx: &CheckCx, original: &Path, built: &Path) -> Result<Option<Likeness>, ToolError> {
    if !(original.is_file() && built.is_file()) {
        return Ok(None);
    }
    let mut params =
        json!({"before": {"path": original.display().to_string()}, "after": {"path": built.display().to_string()}, "common_area": true, "tolerance": 24});
    // The parts of the original that change by themselves (Study's noise-<width>.png) aren't compared.
    let noise =
        original.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_prefix("screenshot-")).map(|w| original.with_file_name(format!("noise-{w}")));
    if let Some(mask) = noise.filter(|m| m.is_file()) {
        params["ignore"] = json!({"path": mask.display().to_string()});
    }
    let r = cx.call("web_pixels_compare", params)?;
    let v = r.to_json();
    let res = v.get("result").cloned().unwrap_or(Value::Null);
    let Some(layout) = res.get("layout_similarity").and_then(Value::as_f64) else { return Ok(None) };
    // Layout alone is generous to mostly empty pages; detail (SSIM) sees text and edges.
    let detail = res.get("perceptual_similarity").and_then(Value::as_f64).unwrap_or(layout);
    let h = |k: &str| res.pointer(&format!("/sizes/{k}/height")).and_then(Value::as_u64).unwrap_or(0);
    Ok(Some(((layout + detail) * 50.0, layout * 100.0, detail * 100.0, h("before"), h("after"))))
}

/// Open the build's menus, pop-ups and tabs the way the study opened the original's in `dir`
/// (`states` or `states-<width>`), at the same width, and compare each pair of pictures. None
/// when the study pictured none there.
fn states_note(cx: &CheckCx, base: &str, out: &Path, dir: &str, unknowns: &mut Vec<String>, claims: &mut Vec<Claim>) -> Result<Option<String>, ToolError> {
    let theirs = cx.ws.capture_dir().join(dir);
    let Some(original) = read_json(&theirs.join("states.json")) else { return Ok(None) };
    if pair_states(&original, &Value::Null).is_empty() {
        return Ok(None);
    }
    let ours = out.join(dir);
    cx.call("web_site_open", json!({"url": base, "settle_ms": 1200}))?;
    // More than the study opened, so the same controls are found even when the build orders them differently.
    let width = original.get("width").and_then(Value::as_u64).unwrap_or(1440);
    if let Err(e) = cx.call("web_page_states_capture", json!({"output_directory": ours.display().to_string(), "max_states": 8, "width": width})) {
        unknowns.push(format!("menus and pop-ups at {width} px couldn't be opened"));
        return Ok(Some(format!("menus and pop-ups couldn't be opened: {}", e.message)));
    }
    let built = read_json(&ours.join("states.json")).unwrap_or(Value::Null);
    let mut parts = Vec::new();
    for (o, b) in pair_states(&original, &built) {
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let name = match s(o, "label") {
            l if l.is_empty() => format!("a {}", s(o, "kind")),
            l => format!("the \"{l}\" {}", s(o, "kind")),
        };
        let likeness = match b {
            Some(b) => picture_likeness(cx, &theirs.join(s(o, "file")), &ours.join(s(b, "file")))?,
            None => None,
        };
        claims.push(Claim::new(format!("{name} opens in the build at {width} px"), b.is_some(), "no such control opens"));
        parts.push(match (b, likeness) {
            (_, Some((score, ..))) => format!("{name} {score:.0}% alike"),
            (Some(_), None) => {
                unknowns.push(format!("{name} at {width} px couldn't be compared"));
                format!("{name} couldn't be compared")
            }
            (None, _) => format!("{name} doesn't open in the build"),
        });
    }
    Ok(Some(format!("opened menus and pop-ups at {width} px: {}", parts.join(", "))))
}

/// Serve the built site on loopback, capture it like the original, and compare screenshots at
/// each width. The likeness is the mean of layout (tile colours) and detail (SSIM of brightness).
/// The note adds the text, the page structure and the opened menus and pop-ups; they guide the
/// builder but don't change the score.
pub struct WebVisualCheck;

/// What the check says when there is no site to look at: the places `site_dir` accepts, in the
/// place the app really is ("app/" or "the project folder", #494).
/// When `app/` holds no files at all, the note says so first: the builder may claim it built the
/// site while nothing was written (#736), and a site can't be found in a folder with no project.
fn missing_site_note(place: &str, empty: bool) -> String {
    let start = if empty { format!("{place} has no files yet, so the builder hasn't written the project. ") } else { String::new() };
    format!(
        "{start}No built site found in {place} yet. Expected an index.html in its dist/, build/ or out/ folder, or an index.html straight in {place} when there is no package.json."
    )
}

impl Check for WebVisualCheck {
    fn id(&self) -> &'static str {
        CheckResult::WEB_VISUAL
    }

    fn run(&self, cx: &mut CheckCx) -> Result<CheckResult, ToolError> {
        let (ws, round) = (cx.ws, cx.round);
        let widths = cx.build_settings().widths();
        let Some(site) = site_dir(&ws.app_dir()) else {
            return Ok(CheckResult::new(self.id(), round, false, missing_site_note(ws.app_place(), app_is_empty(ws))));
        };
        let base = cx.serve_preview(&site)?;
        let out = ws.checks_dir().join(format!("round-{round}"));
        if out.exists() {
            let _ = std::fs::remove_dir_all(&out);
        }
        std::fs::create_dir_all(ws.checks_dir()).map_err(|e| ToolError::io(ws.checks_dir().display(), e))?;
        // The start page, then every other page studied: the same path on the build.
        let mut pages = vec![("start page".to_string(), String::new(), base.clone())];
        let (study_routes, route_warning) = route_list(ws);
        for r in study_routes {
            let url = format!("{}{}", base.trim_end_matches('/'), r.path);
            pages.push((r.path.clone(), format!("routes/{}", r.slug), url));
        }
        let mut scores = Vec::new();
        let mut likeness = Vec::new();
        let mut notes = Vec::new();
        let mut artifacts = Vec::new();
        let mut unknowns = Vec::new();
        let mut claims = Vec::new();
        if let Some(warning) = route_warning {
            unknowns.push(warning);
        }
        if let Some(coverage) = route_coverage(ws) {
            notes.push(route_scope_note(&coverage));
            let unmeasured: Vec<&str> = coverage.boundaries.iter().map(String::as_str).filter(|b| !matches!(*b, "count_limit" | "depth_limit")).collect();
            // A finite quota that was filled still covers the chosen number of pages, even if
            // other candidates failed or exceeded the queue. The note keeps those facts visible.
            let quota_met = coverage.max_pages.is_some_and(|max| coverage.captured >= max);
            if !quota_met && !unmeasured.is_empty() {
                unknowns.push(format!("Route study was partial: {}", unmeasured.join(", ")));
            }
        } else if ws.capture_dir().join(craft_anything_engine::workspace::route_coverage::FILE).exists() {
            unknowns.push("The route-study coverage record could not be read.".into());
        }
        for (name, dir, url) in &pages {
            let (original, built) = if dir.is_empty() { (ws.capture_dir(), out.clone()) } else { (ws.capture_dir().join(dir), out.join(dir)) };
            // web_site_capture creates the page's own folder (it must not exist yet) inside one
            // that does.
            if let Some(parent) = built.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ToolError::io(parent.display(), e))?;
            }
            cx.call("web_site_open", json!({"url": url, "settle_ms": 1200}))?;
            cx.call("web_site_capture", json!({"output_directory": built.display().to_string(), "include_html": false, "widths": widths}))?;
            let mut per_width = Vec::new();
            for &w in &widths {
                let (a, b) = (original.join(format!("screenshot-{w}.png")), built.join(format!("screenshot-{w}.png")));
                match picture_likeness(cx, &a, &b)? {
                    Some((s, l, d, hb, ha)) => {
                        per_width.push((w, s, l, d, hb, ha));
                        artifacts.extend(b.strip_prefix(&ws.root).ok().map(Path::to_path_buf));
                    }
                    // A width the original was never pictured at is outside what was studied;
                    // one it was, that the build's picture can't be compared with, is unknown.
                    None if a.is_file() => unknowns.push(format!("{name} at {w} px couldn't be compared")),
                    None => {}
                }
            }
            if per_width.is_empty() {
                notes.push(format!("{name}: couldn't be compared"));
                continue;
            }
            let score = per_width.iter().map(|p| p.1).sum::<f64>() / per_width.len() as f64;
            scores.push(score);
            likeness.push(PageLikeness { name: name.clone(), dir: dir.clone(), similarity: score });
            let widths = per_width
                .iter()
                .map(|(w, s, l, d, hb, ha)| format!("{w} px: {s:.0}% alike (layout {l:.0}%, detail {d:.0}%; page height {hb} vs {ha} px)"))
                .collect::<Vec<_>>()
                .join("; ");
            // The page's words, parts and measured design too: a build can look alike and still
            // miss words, or get the padding, colours and fonts wrong at some width.
            let page = if dir.is_empty() { "The start page".to_string() } else { name.clone() };
            let text = match (read_json(&original.join("capture.json")), read_json(&built.join("capture.json"))) {
                (Some(o), Some(b)) => {
                    let page_checks = page_claims(&page, &o, &b);
                    if page_checks.len() > 64 {
                        unknowns.push(format!("{name}: more than 64 page claims; the retained prefix does not cover them all"));
                    }
                    claims.extend(page_checks.into_iter().take(64).map(|mut claim| {
                        claim.title = short_note(&claim.title, 256);
                        claim.detail = short_note(&claim.detail, 512);
                        claim
                    }));
                    [text_likeness(&o, &b).map(|t| t.note()), structure_likeness(&o, &b).map(|s| s.note())]
                        .into_iter()
                        .flatten()
                        .chain(design_notes(&o, &b))
                        .chain(health_notes(&o, &b))
                        .map(|n| format!("; {n}"))
                        .collect::<String>()
                }
                _ => String::new(),
            };
            notes.push(short_note(&if pages.len() == 1 { format!("{widths}{text}") } else { format!("{name}: {score:.0}% ({widths}{text})") }, 2048));
        }
        if scores.is_empty() {
            return Ok(CheckResult::new(self.id(), round, false, "The build couldn't be compared with the original."));
        }
        for dir in state_dirs(&ws.capture_dir()) {
            notes.extend(states_note(cx, &base, &out, &dir, &mut unknowns, &mut claims)?);
        }
        let failed: Vec<String> = claims.iter().filter(|c| !c.passed).map(|c| format!("{} ({})", c.title, c.detail)).collect();
        if !failed.is_empty() {
            notes.push(format!(
                "{} of {} claims don't hold yet (first 32 listed): {}",
                failed.len(),
                claims.len(),
                failed.iter().take(32).cloned().collect::<Vec<_>>().join("; ")
            ));
        }
        if !unknowns.is_empty() {
            notes.push(format!("not compared, so this can't pass yet: {}", unknowns.join(", ")));
        }
        let avg = scores.iter().sum::<f64>() / scores.len() as f64;
        // One page needs no list; with several, each one's likeness is kept for the project page.
        let pages = if likeness.len() > 1 { likeness } else { Vec::new() };
        Ok(CheckResult { similarity: Some(avg), artifacts, pages, unknowns, claims, ..CheckResult::new(self.id(), round, true, notes.join(" | ")) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linked(paths: &[&str]) -> Value {
        json!({"url": "https://site.example/", "links": paths.iter().map(|p| json!({"href": format!("https://site.example{p}")})).collect::<Vec<_>>()})
    }

    #[test]
    fn a_late_redirect_or_missing_capture_url_is_not_retained_or_traversed() {
        let root = tempfile::tempdir().unwrap();
        let build = craft_anything_engine::settings::BuildSettings { unlimited_pages: true, max_page_depth: 0, ..Default::default() };
        for final_url in [Some("https://other.example/late"), None] {
            let mut opened = Vec::new();
            let report = capture_routes_with(root.path(), "https://site.example/", &linked(&["/start"]), &build, &CancelToken::default(), |action, route| {
                if action == RouteAction::Open {
                    opened.push(route.path.clone());
                    return Ok(json!({"url": route.url}));
                }
                let mut capture = linked(&["/must-not-follow"]);
                if let Some(url) = final_url {
                    capture["url"] = json!(url);
                } else {
                    capture.as_object_mut().unwrap().remove("url");
                }
                Ok(capture)
            })
            .unwrap();
            assert_eq!(opened, ["/start"]);
            assert_eq!((report.attempted, report.captured), (1, 0));
            let boundary = if final_url.is_some() { "capture_redirected_outside_origin" } else { "capture_url_missing" };
            assert!(report.boundaries.iter().any(|b| b == boundary));
            assert_eq!(report.redirected_outside_origin, usize::from(final_url.is_some()));
            assert_eq!(report.failed, usize::from(final_url.is_none()));
            assert_eq!(read_bounded_json(&root.path().join(ROUTES_FILE), 1024).unwrap(), json!([]));
        }
    }

    #[test]
    fn traversal_honors_more_than_twelve_pages_and_zero_keeps_its_old_meaning() {
        let root = tempfile::tempdir().unwrap();
        let initial = json!({"links": (0..24).map(|i| json!({"href": format!("https://site.example/p{i}")})).collect::<Vec<_>>()});
        for (count, unlimited, expected) in [(18, false, 18), (0, false, 0), (0, true, 24)] {
            let build = craft_anything_engine::settings::BuildSettings { max_pages: count, unlimited_pages: unlimited, ..Default::default() };
            let report = capture_routes_with(root.path(), "https://site.example/", &initial, &build, &CancelToken::default(), |action, route| {
                Ok(if action == RouteAction::Open { json!({"url": route.url}) } else { linked(&[]) })
            })
            .unwrap();
            assert_eq!((report.attempted, report.captured), (expected, expected));
            assert_eq!(report.boundaries.contains(&"count_limit".into()), expected < 24);
        }
    }

    #[test]
    fn finite_page_budgets_can_fill_after_failed_captures() {
        let root = tempfile::tempdir().unwrap();
        let build = craft_anything_engine::settings::BuildSettings { max_pages: 2, ..Default::default() };
        let report = capture_routes_with(
            root.path(),
            "https://site.example/",
            &linked(&["/broken", "/a", "/b", "/c"]),
            &build,
            &CancelToken::default(),
            |action, route| {
                if route.path == "/broken" {
                    return Err(ToolError::invalid("fixture failure"));
                }
                Ok(if action == RouteAction::Open { json!({"url": route.url}) } else { linked(&[]) })
            },
        )
        .unwrap();
        assert_eq!((report.attempted, report.captured, report.failed), (3, 2, 1));
        assert!(report.boundaries.contains(&"count_limit".into()));
    }

    #[test]
    fn traversal_is_breadth_first_and_deduplicates_failed_links_and_cycles() {
        let root = tempfile::tempdir().unwrap();
        let build = craft_anything_engine::settings::BuildSettings { unlimited_pages: true, max_page_depth: 0, ..Default::default() };
        let mut opened = Vec::new();
        let report = capture_routes_with(
            root.path(),
            "https://site.example/",
            &linked(&["/a", "/b", "/broken", "/away"]),
            &build,
            &CancelToken::default(),
            |action, route| {
                if action == RouteAction::Open {
                    opened.push(route.path.clone());
                    return match route.path.as_str() {
                        "/broken" => Err(ToolError::invalid("fixture failure")),
                        "/away" => Ok(json!({"url": "https://other.example/redirected"})),
                        _ => Ok(json!({"url": route.url})),
                    };
                }
                assert_ne!(route.path, "/away", "a foreign redirect is never captured");
                Ok(match route.path.as_str() {
                    "/a" => linked(&["/a", "/b", "/c", "/broken"]),
                    "/b" => linked(&["/a", "/c", "/d", "/away"]),
                    "/c" => linked(&["/e"]),
                    "/e" => linked(&["/a", "/broken"]),
                    _ => linked(&[]),
                })
            },
        )
        .unwrap();
        assert_eq!(opened, ["/a", "/b", "/broken", "/away", "/c", "/d", "/e"]);
        assert_eq!((report.attempted, report.captured, report.failed, report.redirected_outside_origin), (7, 5, 1, 1));
        assert!(same_origin("https://SITE.example:443/start", "https://site.example/elsewhere"));
        assert!(!same_origin("https://site.example/", "https://site.example:444/"));
        assert!(!same_origin("https://site.example/", "https://site.example@other.example/"));
    }

    #[test]
    fn depth_budget_and_cancellation_keep_the_captured_subset() {
        let root = tempfile::tempdir().unwrap();
        let build = craft_anything_engine::settings::BuildSettings { unlimited_pages: true, max_page_depth: 2, ..Default::default() };
        let report = capture_routes_with(root.path(), "https://site.example/", &linked(&["/a"]), &build, &CancelToken::default(), |action, route| {
            Ok(if action == RouteAction::Open {
                json!({"url": route.url})
            } else if route.path == "/a" {
                linked(&["/b"])
            } else {
                linked(&["/c"])
            })
        })
        .unwrap();
        assert_eq!(report.captured, 2);
        assert!(report.boundaries.contains(&"depth_limit".into()));
        let stop = CancelToken::default();
        let error = capture_routes_with(root.path(), "https://site.example/", &linked(&["/a", "/b"]), &build, &stop, |action, route| {
            if action == RouteAction::Open {
                return Ok(json!({"url": route.url}));
            }
            stop.cancel();
            Ok(linked(&[]))
        })
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
        let kept: Vec<Route> = serde_json::from_slice(&std::fs::read(root.path().join(ROUTES_FILE)).unwrap()).unwrap();
        assert_eq!(kept.len(), 1);
        let report =
            RouteCoverage::from_value(read_bounded_json(&root.path().join(craft_anything_engine::workspace::route_coverage::FILE), 65536).unwrap()).unwrap();
        assert_eq!((report.attempted, report.captured), (1, 1));
        assert!(report.boundaries.contains(&"cancelled".into()));
    }

    #[test]
    fn resource_boundaries_and_bounded_readers_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        let initial = json!({"links": (0..300).map(|i| json!({"href": format!("https://site.example/p{i}")})).collect::<Vec<_>>()});
        let build = craft_anything_engine::settings::BuildSettings { unlimited_pages: true, max_page_depth: 0, ..Default::default() };
        let report = capture_routes_with(root.path(), "https://site.example/", &initial, &build, &CancelToken::default(), |action, route| {
            Ok(if action == RouteAction::Open { json!({"url": route.url}) } else { linked(&[]) })
        })
        .unwrap();
        assert_eq!(report.captured, report.resource_limits.retained_routes);
        assert!(report.boundaries.contains(&"frontier_routes".into()));
        let path = root.path().join("large.json");
        std::fs::write(&path, " ".repeat(65)).unwrap();
        assert_eq!(read_bounded_json(&path, 64).unwrap_err().code, ErrorCode::OverLimit);
    }

    #[test]
    fn long_route_briefs_point_to_every_retained_path() {
        let root = tempfile::tempdir().unwrap();
        let ws = Workspace::create(root.path(), "Site", "Rebuild it", TargetRef::Website { url: "https://site.example/".into() }).unwrap();
        let routes: Vec<Route> = (0..40).map(|i| Route { path: format!("/p{i}"), url: format!("https://site.example/p{i}"), slug: format!("p{i}") }).collect();
        save_route_capture(&ws.capture_dir(), &routes, &RouteCoverage { captured: 40, attempted: 40, ..Default::default() }).unwrap();
        let cx = BriefCx { ws: &ws, deep: true, ghidra: false, editor: None, assets: false, image_model: None, sees_pictures: true };
        let brief = WebsiteKind.brief_sections(&cx).join("\n");
        assert!(
            brief.contains("first 32 of 40")
                && brief.contains("capture/routes.json")
                && brief.contains("remaining routes are part of the build and checks too")
        );
        assert_eq!(super::routes(&ws).len(), 40);
    }

    /// #736: an empty app/ is said to be empty, so a builder that claims a build can't hide it; a
    /// folder with files, or a project folder (which always holds the workspace's own), isn't.
    #[test]
    fn an_empty_app_folder_is_named_as_empty() {
        let d = tempfile::tempdir().unwrap();
        let ws = Workspace::create(d.path(), "Site", "Clone it", TargetRef::None).unwrap();
        std::fs::create_dir_all(ws.app_dir()).unwrap();
        assert!(folder_is_empty(&ws.app_dir()), "a new app/ has nothing in it");
        assert!(missing_site_note("app/", true).starts_with("app/ has no files yet"));
        std::fs::write(ws.app_dir().join("package.json"), "{}").unwrap();
        assert!(!folder_is_empty(&ws.app_dir()));
        assert!(!missing_site_note("app/", false).contains("has no files"));
        assert!(folder_is_empty(&d.path().join("never-made")), "a missing folder is empty");
    }

    /// #494: the note names every place `site_dir` accepts, and the place the app really is.
    #[test]
    fn the_missing_site_note_names_what_site_dir_accepts() {
        let note = missing_site_note("app/", false);
        for named in ["dist/", "build/", "out/", "index.html straight in app/", "no package.json"] {
            assert!(note.contains(named), "{named} in {note}");
        }
        assert!(missing_site_note("the project folder", false).contains("index.html straight in the project folder"));
        // What it names is what is accepted, and a manifest turns the plain page down.
        for folder in ["dist", "build", "out"] {
            let d = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(d.path().join(folder)).unwrap();
            std::fs::write(d.path().join(folder).join("index.html"), "<html></html>").unwrap();
            assert_eq!(site_dir(d.path()), Some(d.path().join(folder)), "{folder}");
        }
        let d = tempfile::tempdir().unwrap();
        assert_eq!(site_dir(d.path()), None, "nothing built");
        std::fs::write(d.path().join("index.html"), "<html></html>").unwrap();
        assert_eq!(site_dir(d.path()), Some(d.path().to_path_buf()), "a plain page");
        std::fs::write(d.path().join("package.json"), "{}").unwrap();
        assert_eq!(site_dir(d.path()), None, "a page beside a manifest is not a built site");
    }
}
