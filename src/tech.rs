//! Additive technology fingerprinting for `ftw probe`.
//!
//! Input is the already-fetched probe response only: status, headers, final
//! URL, and a body preview of at most [`MAX_PREVIEW_BYTES`] bytes kept in
//! memory for parsing and then discarded. This module makes no network
//! requests of its own: it never fetches linked CSS/JS and never requests any
//! additional path (no `/wp-admin`, `/wp-login.php`, `/phpinfo.php`,
//! `/readme.html`, `/xmlrpc.php`, no POST, no logins).
//!
//! Parsing uses the `scraper` crate to extract meta tags, link hrefs,
//! script/img srcs, class attributes, and title text from the preview. Raw
//! HTML is never regexed for tag attributes. The only raw-text searches are
//! the exact phrases the spec allows: `"Powered by phpBB"` and
//! `"Drupal.settings"` in the preview text.
//!
//! `Link` response headers are parsed into the same `(href, rel)` shape as
//! HTML `<link>` tags, so header signals count whether they arrive on HEAD
//! or on GET. `head_identifies_app` reports when HEAD headers alone
//! definitively identify the application and the GET can be skipped.
//!
//! Known limitations (by design, not bugs):
//! - Only the first [`MAX_PREVIEW_BYTES`] (64 KiB) bytes of a body are
//!   fingerprinted; larger pages are not fully fetched.
//! - Linked CSS is never fetched, so `--tw-*` variable checks are out of scope.
//! - Laravel, Symfony, and other PHP frameworks are deliberately not detected
//!   from a single GET: there is no reliable marker, so they are left out
//!   rather than guessed.

use reqwest::header::HeaderMap;
use scraper::{Html, Selector};

/// At most this many leading body bytes are kept for parsing, then discarded.
pub const MAX_PREVIEW_BYTES: usize = 65536;

/// One detected PHP application: `{name, version, signals}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhpApp {
    pub name: String,
    pub version: Option<String>,
    pub signals: Vec<String>,
}

/// Technology signals derived from one already-fetched response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechFingerprint {
    pub wordpress_detected: bool,
    pub wordpress_version: Option<String>,
    pub wordpress_signals: Vec<String>,
    pub php_apps: Vec<PhpApp>,
    pub tailwind_detected: bool,
    pub tailwind_confidence: String,
    pub tailwind_signals: Vec<String>,
}

/// Fingerprint the already-fetched response. `_status` and `_final_url` are
/// part of the response contract even though no current tech signal needs
/// them; they are accepted so callers pass the whole response shape.
pub fn fingerprint_tech(
    _status: Option<u16>,
    headers: &HeaderMap,
    _final_url: &str,
    body_preview: &str,
) -> TechFingerprint {
    let document = Html::parse_document(body_preview);
    let generators = generator_contents(&document);
    let links = link_hrefs(&document);
    let script_srcs = attr_values(&document, "script", "src");
    let img_srcs = attr_values(&document, "img", "src");
    let mut srcs: Vec<&str> = Vec::with_capacity(links.len() + script_srcs.len() + img_srcs.len());
    for (href, _) in &links {
        srcs.push(href.as_str());
    }
    for src in &script_srcs {
        srcs.push(src.as_str());
    }
    for src in &img_srcs {
        srcs.push(src.as_str());
    }
    let title = page_title(&document);

    // Header `Link` entries feed the WordPress check only, so the existing
    // `wp-json` matching applies unchanged to HEAD and GET headers alike.
    // Tailwind and src signals stay HTML-only, exactly as specified.
    let mut wordpress_links = links.clone();
    wordpress_links.extend(link_header_hrefs(headers));
    let (wordpress_detected, wordpress_version, wordpress_signals) =
        wordpress(&generators, &srcs, &wordpress_links);
    let php_apps = php_apps(headers, &generators, &srcs, &title, body_preview, &document);
    let (tailwind_detected, tailwind_confidence, tailwind_signals) =
        tailwind(&links, &script_srcs, &document);

    TechFingerprint {
        wordpress_detected,
        wordpress_version,
        wordpress_signals,
        php_apps,
        tailwind_detected,
        tailwind_confidence,
        tailwind_signals,
    }
}

/// `content` of every `<meta name="generator">` tag (`name` matched
/// case-insensitively, as HTML attribute names are ASCII case-insensitive).
fn generator_contents(document: &Html) -> Vec<String> {
    let Some(selector) = Selector::parse("meta").ok() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for element in document.select(&selector) {
        let value = element.value();
        let is_generator = value.attr("name").is_some_and(|name| name.eq_ignore_ascii_case("generator"));
        if is_generator {
            if let Some(content) = value.attr("content") {
                out.push(content.to_string());
            }
        }
    }
    out
}

/// `(href, rel)` of every `<link href>` tag.
fn link_hrefs(document: &Html) -> Vec<(String, String)> {
    let Some(selector) = Selector::parse("link").ok() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            let rel = element.value().attr("rel").unwrap_or_default();
            out.push((href.to_string(), rel.to_string()));
        }
    }
    out
}

/// `(href, rel)` of every `Link` response header entry, in the same shape as
/// [`link_hrefs`], so the WordPress `wp-json` match applies to headers from
/// HEAD or GET alike. Segments are split on commas only; no regex is used.
fn link_header_hrefs(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for value in headers.get_all("link").iter() {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for segment in text.split(',') {
            let Some(uri) = segment
                .split('<')
                .nth(1)
                .and_then(|rest| rest.split('>').next())
            else {
                continue;
            };
            let uri = uri.trim();
            if uri.is_empty() {
                continue;
            }
            out.push((uri.to_string(), parse_link_rel(segment).unwrap_or_default()));
        }
    }
    out
}

/// Parse the `rel` parameter out of one `Link` link-value segment, handling
/// `rel="https://api.w.org/"` and bare `rel=preload` forms. Returns `None`
/// when the segment carries no `rel` parameter.
fn parse_link_rel(segment: &str) -> Option<String> {
    let mut rest = segment;
    while let Some(index) = rest.find("rel") {
        let before_ok = index == 0 || matches!(rest.as_bytes()[index - 1], b';' | b' ' | b'\t');
        let after = rest[index + 3..].trim_start();
        rest = &rest[index + 3..];
        if !before_ok {
            continue;
        }
        let Some(value) = after.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        if let Some(quoted) = value.strip_prefix('"') {
            let end = quoted.find('"')?;
            return Some(quoted[..end].to_string());
        }
        let end = value.find([';', ' ', '\t']).unwrap_or(value.len());
        if end == 0 {
            continue;
        }
        return Some(value[..end].to_string());
    }
    None
}

/// True when HEAD headers alone definitively identify the application, so
/// the GET can be skipped: a `Link` header for `/wp-json/` with rel
/// `https://api.w.org/` (WordPress), or any `X-Magento-*` header (Magento).
/// Keep in sync with the `wp-json` match in [`wordpress`] and the
/// `x-magento-header` match in [`php_apps`]. PHP-only headers
/// (`X-Powered-By`, PHPSESSID) are NOT sufficient: application and Tailwind
/// signals live in the HTML, so those still require the GET.
pub fn head_identifies_app(headers: &HeaderMap) -> bool {
    if headers
        .keys()
        .any(|name| name.as_str().to_lowercase().starts_with("x-magento-"))
    {
        return true;
    }
    link_header_hrefs(headers)
        .iter()
        .any(|(href, rel)| rel == "https://api.w.org/" && href.contains("/wp-json/"))
}

/// `attr` of every `tag` element carrying it (e.g. `script`/`src`).
fn attr_values(document: &Html, tag: &str, attr: &str) -> Vec<String> {
    let Ok(selector) = Selector::parse(tag) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for element in document.select(&selector) {
        if let Some(value) = element.value().attr(attr) {
            out.push(value.to_string());
        }
    }
    out
}

/// Text of the first `<title>` element, or empty when absent.
fn page_title(document: &Html) -> String {
    let Ok(selector) = Selector::parse("title") else {
        return String::new();
    };
    document
        .select(&selector)
        .next()
        .map(|element| element.text().collect::<String>())
        .unwrap_or_default()
}

/// True when any element carries an attribute whose name starts with
/// `data-drupal-` (checked via the parsed DOM, never via raw-HTML regex).
fn has_data_drupal_attr(document: &Html) -> bool {
    let Ok(star) = Selector::parse("*") else {
        return false;
    };
    for element in document.select(&star) {
        for (name, _) in element.value().attrs() {
            if name.to_lowercase().starts_with("data-drupal-") {
                return true;
            }
        }
    }
    false
}

/// Parse `WordPress <version>` from generator content (e.g.
/// `"WordPress 6.5.2"` gives `"6.5.2"`); anything else gives `None`. The
/// version token must be digits and dots only. Never guessed.
fn parse_wordpress_version(content: &str) -> Option<String> {
    let rest = content.strip_prefix("WordPress ")?.trim();
    if rest.is_empty() {
        return None;
    }
    let token: &str = rest.split_whitespace().next()?;
    let token = token.trim_matches([',', ';', '(', ')']);
    if token.is_empty()
        || !token.chars().all(|c| c.is_ascii_digit() || c == '.')
        || !token.chars().any(|c| c.is_ascii_digit())
        || token.contains("..")
        || token.starts_with('.')
        || token.ends_with('.')
    {
        return None;
    }
    Some(token.to_string())
}

/// First version-like run (`1`, `10`, `1.35`, `3.9.0`) in generator text, or
/// `None` when there is no number. Used only for the app whose generator
/// marker already matched; never invented from another source.
fn extract_version(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                index += 1;
            }
            let mut candidate = text[start..index].trim_matches('.');
            // Avoid swallowing a trailing dot run left by trimming.
            while candidate.ends_with('.') {
                candidate = candidate.trim_matches('.');
            }
            let valid = !candidate.is_empty()
                && !candidate.contains("..")
                && candidate
                    .split('.')
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
            if valid {
                return Some(candidate.to_string());
            }
        } else {
            index += 1;
        }
    }
    None
}

/// WordPress signals. `wordpress_detected` is true if and only if a strong
/// signal (`generator`, `wp-content`, `wp-includes`, `wp-json`) is present.
/// `woocommerce-plugin` is recorded when present but never reported as a
/// separate application.
fn wordpress(
    generators: &[String],
    srcs: &[&str],
    links: &[(String, String)],
) -> (bool, Option<String>, Vec<String>) {
    let mut signals = Vec::new();
    if generators.iter().any(|content| content.starts_with("WordPress ")) {
        signals.push("generator".to_string());
    }
    if srcs.iter().any(|src| src.contains("/wp-content/")) {
        signals.push("wp-content".to_string());
    }
    if srcs.iter().any(|src| src.contains("/wp-includes/")) {
        signals.push("wp-includes".to_string());
    }
    if links
        .iter()
        .any(|(href, rel)| rel == "https://api.w.org/" && href.contains("/wp-json/"))
    {
        signals.push("wp-json".to_string());
    }
    if srcs
        .iter()
        .any(|src| src.contains("/wp-content/plugins/woocommerce/"))
    {
        signals.push("woocommerce-plugin".to_string());
    }
    let detected = signals
        .iter()
        .any(|signal| matches!(signal.as_str(), "generator" | "wp-content" | "wp-includes" | "wp-json"));
    let version = generators.iter().find_map(|content| parse_wordpress_version(content));
    (detected, version, signals)
}

/// General PHP application list. WordPress is excluded here to avoid
/// duplication (it has dedicated fields). Laravel/Symfony and other
/// frameworks are deliberately absent: no reliable single-GET marker.
#[allow(clippy::too_many_arguments)]
fn php_apps(
    headers: &HeaderMap,
    generators: &[String],
    srcs: &[&str],
    title: &str,
    body_preview: &str,
    document: &Html,
) -> Vec<PhpApp> {
    let mut apps = Vec::new();

    let joomla_generator = generators.iter().find(|content| content.contains("Joomla!"));
    let mut joomla_signals = Vec::new();
    if joomla_generator.is_some() {
        joomla_signals.push("generator".to_string());
    }
    if srcs.iter().any(|src| src.contains("/media/system/")) {
        joomla_signals.push("media-system".to_string());
    }
    if srcs.iter().any(|src| src.contains("/media/jui/")) {
        joomla_signals.push("media-jui".to_string());
    }
    if !joomla_signals.is_empty() {
        apps.push(PhpApp {
            name: "Joomla".to_string(),
            version: joomla_generator.and_then(|content| extract_version(content)),
            signals: joomla_signals,
        });
    }

    let drupal_generator = generators.iter().find(|content| content.contains("Drupal"));
    let mut drupal_signals = Vec::new();
    if drupal_generator.is_some() {
        drupal_signals.push("generator".to_string());
    }
    if srcs.iter().any(|src| src.contains("/sites/default/files")) {
        drupal_signals.push("sites-files".to_string());
    }
    if has_data_drupal_attr(document) {
        drupal_signals.push("data-drupal-attr".to_string());
    }
    if body_preview.contains("Drupal.settings") {
        drupal_signals.push("drupal-settings".to_string());
    }
    if !drupal_signals.is_empty() {
        apps.push(PhpApp {
            name: "Drupal".to_string(),
            version: drupal_generator.and_then(|content| extract_version(content)),
            signals: drupal_signals,
        });
    }

    let mut magento_signals = Vec::new();
    if headers
        .keys()
        .any(|name| name.as_str().to_lowercase().starts_with("x-magento-"))
    {
        magento_signals.push("x-magento-header".to_string());
    }
    if srcs.iter().any(|src| src.contains("/static/frontend/")) {
        magento_signals.push("static-frontend".to_string());
    }
    if srcs.iter().any(|src| src.contains("/static/version")) {
        magento_signals.push("static-version".to_string());
    }
    if !magento_signals.is_empty() {
        apps.push(PhpApp {
            name: "Magento".to_string(),
            version: None,
            signals: magento_signals,
        });
    }

    let mut phpbb_signals = Vec::new();
    if body_preview.contains("Powered by phpBB") {
        phpbb_signals.push("powered-by".to_string());
    }
    if srcs.iter().any(|src| src.contains("/styles/")) && title.contains("phpBB") {
        phpbb_signals.push("styles-with-title".to_string());
    }
    if !phpbb_signals.is_empty() {
        apps.push(PhpApp {
            name: "phpBB".to_string(),
            version: None,
            signals: phpbb_signals,
        });
    }

    let mediawiki_generator = generators.iter().find(|content| content.contains("MediaWiki"));
    let mut mediawiki_signals = Vec::new();
    if mediawiki_generator.is_some() {
        mediawiki_signals.push("generator".to_string());
    }
    if srcs.iter().any(|src| src.contains("/load.php")) {
        mediawiki_signals.push("load-php".to_string());
    }
    if !mediawiki_signals.is_empty() {
        apps.push(PhpApp {
            name: "MediaWiki".to_string(),
            version: mediawiki_generator.and_then(|content| extract_version(content)),
            signals: mediawiki_signals,
        });
    }

    let prestashop_generator = generators.iter().find(|content| content.contains("PrestaShop"));
    let mut prestashop_signals = Vec::new();
    if prestashop_generator.is_some() {
        prestashop_signals.push("generator".to_string());
    }
    if srcs
        .iter()
        .any(|src| src.to_lowercase().contains("prestashop"))
    {
        prestashop_signals.push("prestashop-src".to_string());
    }
    if !prestashop_signals.is_empty() {
        apps.push(PhpApp {
            name: "PrestaShop".to_string(),
            version: prestashop_generator.and_then(|content| extract_version(content)),
            signals: prestashop_signals,
        });
    }

    let mut opencart_signals = Vec::new();
    if srcs.iter().any(|src| src.contains("catalog/view/")) {
        opencart_signals.push("catalog-view".to_string());
    }
    if !opencart_signals.is_empty() {
        apps.push(PhpApp {
            name: "OpenCart".to_string(),
            version: None,
            signals: opencart_signals,
        });
    }

    let moodle_generator = generators.iter().find(|content| content.contains("Moodle"));
    let mut moodle_signals = Vec::new();
    if moodle_generator.is_some() {
        moodle_signals.push("generator".to_string());
    }
    if srcs.iter().any(|src| src.contains("/theme/styles.php")) {
        moodle_signals.push("theme-styles".to_string());
    }
    if !moodle_signals.is_empty() {
        apps.push(PhpApp {
            name: "Moodle".to_string(),
            version: moodle_generator.and_then(|content| extract_version(content)),
            signals: moodle_signals,
        });
    }

    apps
}

/// TailwindCSS signals from the same preview. `tailwind_detected` is true if
/// and only if a strong signal is present; utility classes alone give
/// confidence `"weak"`, never a confirmed detection.
fn tailwind(
    links: &[(String, String)],
    script_srcs: &[String],
    document: &Html,
) -> (bool, String, Vec<String>) {
    let mut signals = Vec::new();
    if script_srcs
        .iter()
        .any(|src| src.to_lowercase().contains("cdn.tailwindcss.com"))
    {
        signals.push("tailwind-cdn".to_string());
    }
    if links
        .iter()
        .any(|(href, _)| href.to_lowercase().contains("tailwind"))
    {
        signals.push("tailwind-link".to_string());
    }
    if tailwind_utility_hits(document) >= 3 {
        signals.push("utility-classes".to_string());
    }
    let detected = signals
        .iter()
        .any(|signal| signal == "tailwind-cdn" || signal == "tailwind-link");
    let confidence = if detected {
        "strong"
    } else if signals.iter().any(|signal| signal == "utility-classes") {
        "weak"
    } else {
        "none"
    };
    (detected, confidence.to_string(), signals)
}

/// Count class tokens matching Tailwind utility patterns (`flex`, `grid`,
/// `px-*`, `py-*`, `gap-*`, `items-*`, `justify-*`, `text-*`, `bg-*`,
/// `rounded-*`, `shadow-*`). Variant prefixes (`md:flex`, `hover:bg-red-500`)
/// are stripped before matching.
fn tailwind_utility_hits(document: &Html) -> usize {
    let Ok(selector) = Selector::parse("[class]") else {
        return 0;
    };
    let mut hits = 0;
    for element in document.select(&selector) {
        if let Some(classes) = element.value().attr("class") {
            for token in classes.split_whitespace() {
                if is_tailwind_utility(token) {
                    hits += 1;
                }
            }
        }
    }
    hits
}

fn is_tailwind_utility(token: &str) -> bool {
    let base = token.rsplit(':').next().unwrap_or(token);
    let base = base.trim_start_matches(['!', '-']);
    if base == "flex" || base.starts_with("flex-") || base == "grid" || base.starts_with("grid-") {
        return true;
    }
    const PREFIXES: &[&str] = &[
        "px-", "py-", "gap-", "items-", "justify-", "text-", "bg-", "rounded-", "shadow-",
    ];
    PREFIXES.iter().any(|prefix| base.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> HeaderMap {
        HeaderMap::new()
    }

    #[test]
    fn wordpress_generator_and_content_signals() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.5.2" /><script src="/wp-content/themes/t/app.js"></script></head></html>"#;
        let tech = fingerprint_tech(None, &headers(), "http://127.0.0.1/", body);
        assert!(tech.wordpress_detected);
        assert_eq!(tech.wordpress_version.as_deref(), Some("6.5.2"));
        assert!(tech.wordpress_signals.contains(&"generator".to_string()));
        assert!(tech.wordpress_signals.contains(&"wp-content".to_string()));
        assert!(tech.php_apps.is_empty(), "WordPress must not duplicate into php_apps");
    }

    #[test]
    fn joomla_version_parsed_from_generator() {
        let body = r#"<html><head><meta name="generator" content="Joomla! 4.2.5" /></head></html>"#;
        let tech = fingerprint_tech(None, &headers(), "http://127.0.0.1/", body);
        assert!(!tech.wordpress_detected);
        let app = tech.php_apps.iter().find(|app| app.name == "Joomla").expect("Joomla entry");
        assert_eq!(app.version.as_deref(), Some("4.2.5"));
    }

    #[test]
    fn plain_html_has_no_signals() {
        let body = "<html><head><title>Hello</title></head><body><p>hello</p></body></html>";
        let tech = fingerprint_tech(None, &headers(), "http://127.0.0.1/", body);
        assert!(!tech.wordpress_detected);
        assert!(tech.wordpress_signals.is_empty());
        assert!(tech.php_apps.is_empty());
        assert!(!tech.tailwind_detected);
        assert_eq!(tech.tailwind_confidence, "none");
    }

    #[test]
    fn link_header_wp_json_identifies_wordpress_without_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "link",
            "<https://example.com/wp-json/>; rel=\"https://api.w.org/\""
                .parse()
                .expect("link header"),
        );
        assert!(head_identifies_app(&headers));
        let tech = fingerprint_tech(None, &headers, "http://127.0.0.1/", "");
        assert!(tech.wordpress_detected);
        assert!(tech.wordpress_signals.contains(&"wp-json".to_string()));
        assert!(tech.php_apps.is_empty());
    }

    #[test]
    fn php_only_headers_do_not_identify_app() {
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", "PHP/8.2.0".parse().expect("powered-by"));
        assert!(!head_identifies_app(&headers));
        let tech = fingerprint_tech(None, &headers, "http://127.0.0.1/", "");
        assert!(!tech.wordpress_detected);
    }

    #[test]
    fn tailwind_cdn_is_strong_but_utilities_alone_are_weak() {
        let strong = r#"<html><head><script src="https://cdn.tailwindcss.com"></script></head><body><div class="plain">hi</div></body></html>"#;
        let tech = fingerprint_tech(None, &headers(), "http://127.0.0.1/", strong);
        assert!(tech.tailwind_detected);
        assert_eq!(tech.tailwind_confidence, "strong");

        let weak = r#"<html><body><div class="flex items-center justify-center">hi</div></body></html>"#;
        let tech = fingerprint_tech(None, &headers(), "http://127.0.0.1/", weak);
        assert!(!tech.tailwind_detected, "utility classes alone are never confirmed");
        assert_eq!(tech.tailwind_confidence, "weak");
    }
}
