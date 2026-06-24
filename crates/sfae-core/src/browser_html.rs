//! HTML rendering, form parsing, and URL decoding helpers for the browser-based credential prompt.
//!
//! Split out from `browser.rs` to keep that module under the file-length limit.

use std::collections::HashMap;

#[cfg(feature = "cli")]
use crate::spec::{FieldSpec, GroupSpec, OAuthSpec, PromptSpec};

/// Shared CSS included in both form and done pages.
pub(crate) const BASE_STYLES: &str = include_str!("base.css");

/// A path string paired with the query-parameter key to extract.
pub struct QueryLookup<'a> {
    pub path: &'a str,
    pub key: &'a str,
}

/// Shared context for the browser-based form flow.
#[cfg(feature = "cli")]
pub struct FormContext<'a> {
    pub domain: &'a str,
    pub label: &'a str,
    pub credential_label: Option<&'a str>,
    pub spec: &'a PromptSpec,
}

/// Collect common (non-group) fields from a PromptSpec.
#[cfg(feature = "cli")]
pub(crate) fn collect_common_fields(spec: &PromptSpec) -> Vec<FieldSpec> {
    let mut fields = Vec::new();
    if let Some(ref f) = spec.fields {
        fields.extend(f.iter().cloned());
    }
    fields
}

/// Extract a query parameter value from a path like `/callback?code=abc&state=xyz`.
pub(crate) fn extract_query_param(lookup: QueryLookup<'_>) -> Option<String> {
    let QueryLookup { path, key } = lookup;
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix(&format!("{key}=")) {
            return Some(url_decode(value));
        }
    }
    None
}

/// Build the HTML form page with data-driven fields and optional groups.
#[cfg(feature = "cli")]
pub(crate) fn build_form_page(ctx: FormContext<'_>) -> String {
    let FormContext { label, spec, .. } = ctx;
    let url_section = match spec.help_url.as_deref() {
        Some(u) => format!(
            r#"<p class="url-hint">Obtain your credential here:<br><a href="{}" target="_blank">{}</a></p>"#,
            html_escape(u),
            html_escape(u),
        ),
        None => String::new(),
    };

    let common_fields = collect_common_fields(spec);
    let has_common = !common_fields.is_empty();
    let fields_html = FieldsRender {
        fields: &common_fields,
        autofocus_first: true,
        index_offset: 0,
    }
    .render();
    let groups = spec.groups.as_deref().unwrap_or(&[]);
    let groups_html = GroupsRender {
        groups,
        autofocus_first_group: !has_common,
        field_index_offset: common_fields.len(),
    }
    .render();

    // Hide the submit button when the only content is OAuth (no input fields).
    let has_any_input_fields = has_common
        || groups
            .iter()
            .any(|g| g.fields.as_ref().is_some_and(|f| !f.is_empty()));
    let submit_button = if has_any_input_fields {
        r#"<button type="button" onclick="sfaeSubmit()">Submit</button>"#
    } else {
        ""
    };

    apply_template(Template {
        source: include_str!("form.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{LABEL}}", &html_escape(label)),
            ("{{URL_SECTION}}", &url_section),
            ("{{FIELDS}}", &fields_html),
            ("{{GROUPS}}", &groups_html),
            ("{{SUBMIT_BUTTON}}", submit_button),
        ],
    })
}

/// Parameters for rendering a list of form fields as HTML.
#[cfg(feature = "cli")]
struct FieldsRender<'a> {
    fields: &'a [FieldSpec],
    autofocus_first: bool,
    index_offset: usize,
}

#[cfg(feature = "cli")]
impl<'a> FieldsRender<'a> {
    /// Generate HTML for a list of field specs.
    fn render(&self) -> String {
        let FieldsRender {
            fields,
            autofocus_first,
            index_offset,
        } = *self;
        let mut html = String::new();
        for (i, field) in fields.iter().enumerate() {
            // All field identifiers are opaque to defeat Safari/macOS Passwords
            // heuristics. Names like "PASSWORD" or "ACCESS_TOKEN" trigger the
            // "Save Password?" dialog. We use `_f0`, `_f1`, … and the server
            // maps them back by index.
            let idx = index_offset + i;
            let opaque_name = format!("_f{idx}");
            let label = html_escape(&field.display_label());
            let autofocus = if autofocus_first && i == 0 {
                " autofocus"
            } else {
                ""
            };
            let value = field
                .default
                .as_ref()
                .map(|d| format!(r#" value="{}""#, html_escape(d)))
                .unwrap_or_default();
            let data_required = if field.is_optional() {
                ""
            } else {
                r#" data-required="true""#
            };
            let optional_hint = if field.is_optional() {
                r#" <span class="optional-hint">(optional)</span>"#
            } else {
                ""
            };
            if field.is_secret() {
                html.push_str(&format!(
                    r#"<div class="field"><label>{label}{optional_hint}</label><div style="position:relative"><input type="text" name="{opaque_name}"{value}{autofocus}{data_required} data-m="1"><span class="dots" aria-hidden="true"></span></div></div>"#,
                ));
            } else {
                html.push_str(&format!(
                    r#"<div class="field"><label>{label}{optional_hint}</label><input type="text" name="{opaque_name}"{value}{autofocus}{data_required}></div>"#,
                ));
            }
        }
        html
    }
}

/// Parameters for rendering alternative field groups.
#[cfg(feature = "cli")]
struct GroupsRender<'a> {
    groups: &'a [GroupSpec],
    autofocus_first_group: bool,
    field_index_offset: usize,
}

#[cfg(feature = "cli")]
impl<'a> GroupsRender<'a> {
    /// Generate HTML for alternative field groups with tab selector and toggle script.
    fn render(&self) -> String {
        let GroupsRender {
            groups,
            autofocus_first_group,
            field_index_offset,
        } = *self;
        if groups.is_empty() {
            return String::new();
        }

        let mut html = String::from(r#"<div class="groups">"#);

        // Only show the tab bar when there are multiple groups to choose between.
        if groups.len() > 1 {
            html.push_str(r#"<div class="group-tabs">"#);
            for (i, group) in groups.iter().enumerate() {
                let checked = if i == 0 { " checked" } else { "" };
                let label = html_escape(&group.label);
                html.push_str(&format!(
                    r#"<label class="group-tab"><input type="radio" name="_group" value="{i}"{checked}><span>{label}</span></label>"#,
                ));
            }
            html.push_str("</div>");
        } else {
            // Single group: emit a hidden input so the server still knows which group.
            html.push_str(r#"<input type="hidden" name="_group" value="0">"#);
        }

        for (i, group) in groups.iter().enumerate() {
            let hidden = if i == 0 {
                ""
            } else {
                r#" style="display:none""#
            };
            html.push_str(&format!(
                r#"<div class="group-panel" data-group="{i}"{hidden}>"#,
            ));
            if let Some(oauth) = &group.oauth {
                html.push_str(
                    &OAuthPanel {
                        oauth,
                        group_idx: i,
                    }
                    .render(),
                );
            } else if let Some(fields) = &group.fields {
                html.push_str(
                    &FieldsRender {
                        fields,
                        autofocus_first: autofocus_first_group && i == 0,
                        index_offset: field_index_offset,
                    }
                    .render(),
                );
            }
            html.push_str("</div>");
        }

        html.push_str("</div>");

        // Inline JS for group toggling and OAuth status polling.
        html.push_str(concat!(
            "<script>(function(){",
            "function u(v){",
            "document.querySelectorAll('.group-panel').forEach(function(p){",
            "var a=p.dataset.group===v;",
            "p.style.display=a?'':'none';",
            "p.querySelectorAll('input:not([name=\"_group\"])').forEach(function(i){i.disabled=!a})",
            "})}",
            "var c=document.querySelector('input[name=\"_group\"]:checked');",
            "if(c)u(c.value);",
            "document.querySelectorAll('input[name=\"_group\"]').forEach(function(r){",
            "r.addEventListener('change',function(){u(r.value)})",
            "});",
            "var oa=document.querySelector('.oauth-content');",
            "if(oa){var t=setInterval(function(){",
            "fetch('/oauth-status').then(function(r){return r.json()}).then(function(d){",
            "if(d.authorized){",
            "clearInterval(t);",
            "document.querySelectorAll('.oauth-btn').forEach(function(b){b.style.display='none'});",
            "document.querySelectorAll('.oauth-status').forEach(function(s){s.style.display='flex'});",
            "var inputs=document.querySelectorAll('input[type=\"text\"]:not(:disabled)');",
            "if(!inputs.length){sfaeSubmit()}",
            "}else if(d.error){",
            "clearInterval(t);",
            "document.querySelectorAll('.oauth-status').forEach(function(s){s.style.display='flex';s.textContent='Authorization failed'});",
            "sfaeSubmit();",
            "}",
            "}).catch(function(){})",
            "},1500)}",
            "})()</script>",
        ));

        html
    }
}

/// Parameters for rendering a single OAuth group panel.
#[cfg(feature = "cli")]
struct OAuthPanel<'a> {
    oauth: &'a OAuthSpec,
    group_idx: usize,
}

#[cfg(feature = "cli")]
impl<'a> OAuthPanel<'a> {
    /// Generate HTML for an OAuth group panel: scope display + "Authorize" button.
    fn render(&self) -> String {
        let scopes = self.oauth.requested_scopes();
        let scope = if scopes.is_empty() {
            "default".to_string()
        } else {
            scopes.join(" ")
        };
        let scope = html_escape(&scope);
        let group_idx = self.group_idx;
        let mut html = String::new();
        html.push_str(r#"<div class="oauth-content">"#);
        html.push_str(&format!(
            r#"<p class="oauth-scope">Scope: <code>{scope}</code></p>"#,
        ));
        html.push_str(&format!(
            r#"<a href="/auth?group={group_idx}" class="oauth-btn" id="oauth-btn-{group_idx}">Authorize</a>"#,
        ));
        html.push_str(&format!(
            r#"<div class="oauth-status" id="oauth-status-{group_idx}" style="display:none">&#10003; Authorized</div>"#,
        ));
        html.push_str("</div>");
        html
    }
}

/// A template source plus substitution pairs used to fill `{{VARS}}`.
struct Template<'a> {
    source: &'a str,
    vars: &'a [(&'a str, &'a str)],
}

/// Apply a sequence of `{{KEY}} → value` substitutions to a template string.
fn apply_template(tpl: Template<'_>) -> String {
    let mut out = tpl.source.to_string();
    for (key, value) in tpl.vars {
        out = out.replace(key, value);
    }
    out
}

/// Build the confirmation page shown after the secret is submitted or OAuth completes.
pub(crate) fn build_done_page() -> String {
    apply_template(Template {
        source: include_str!("done.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{TITLE}}", "sfae \u{2014} done"),
            ("{{HEADING}}", "Credential saved"),
        ],
    })
}

/// Minimal HTML escaping for user-provided strings embedded in HTML.
#[cfg(feature = "cli")]
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Parse all key=value pairs from a `application/x-www-form-urlencoded` body.
#[cfg(feature = "cli")]
pub(crate) fn parse_form_fields(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in body.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            map.insert(url_decode(key), url_decode(value));
        }
    }
    map
}

/// Minimal percent-decoding for form values.
fn url_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
            {
                result.push(byte);
                i += 3;
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;

    #[test]
    fn oauth_authorize_link_reuses_current_tab() {
        let panel = OAuthPanel {
            oauth: &OAuthSpec {
                provider: Some("discord".to_string()),
                scope: Some("identify email".to_string()),
                scopes: vec![],
            },
            group_idx: 0,
        };

        let html = panel.render();

        assert!(html.contains(r#"href="/auth?group=0""#));
        assert!(html.contains(r#"class="oauth-btn""#));
        assert!(!html.contains("target="));
    }
}
