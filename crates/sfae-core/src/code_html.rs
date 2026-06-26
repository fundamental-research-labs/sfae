//! HTML rendering helpers for the transient one-time code browser page.

use crate::browser_html::{BASE_SCRIPT, BASE_STYLES};
use crate::code::{CodeFormat, CodeRequest};

pub(crate) struct CodePageContext<'a> {
    pub request: &'a CodeRequest,
    pub csrf_token: &'a str,
    pub error: Option<&'a str>,
    pub timeout_secs: u64,
}

pub(crate) fn build_code_page(ctx: CodePageContext<'_>) -> String {
    let request = ctx.request;
    let heading = format!("Verification code for {}", request.domain);
    let meta = request
        .label
        .as_ref()
        .map(|label| format!(r#"<p class="meta">{}</p>"#, html_escape(label)))
        .unwrap_or_default();
    let message = request
        .message
        .as_deref()
        .unwrap_or("Enter the code the service sent or displayed.");
    let help_section = request
        .help_url
        .as_ref()
        .map(|url| {
            format!(
                r#"<p class="help-link"><a href="{}" target="_blank" rel="noreferrer">Open verification page</a></p>"#,
                html_escape(url),
            )
        })
        .unwrap_or_default();
    let error_section = ctx
        .error
        .map(|error| {
            format!(
                r#"<p class="error" role="alert">{}</p>"#,
                html_escape(error)
            )
        })
        .unwrap_or_default();
    let pattern = match request.format {
        CodeFormat::Digits => r#" pattern="[0-9]*""#,
        CodeFormat::Alnum => r#" pattern="[A-Za-z0-9]*""#,
        CodeFormat::Text => "",
    };

    apply_template(Template {
        source: include_str!("code.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{BASE_SCRIPT}}", BASE_SCRIPT),
            ("{{TITLE}}", "sfae - verification code"),
            ("{{HEADING}}", &html_escape(&heading)),
            ("{{META}}", &meta),
            ("{{MESSAGE}}", &html_escape(message)),
            ("{{HELP_SECTION}}", &help_section),
            ("{{ERROR_SECTION}}", &error_section),
            ("{{CSRF}}", &html_escape(ctx.csrf_token)),
            ("{{INPUTMODE}}", input_mode(request.format)),
            ("{{PATTERN_ATTR}}", pattern),
            ("{{MIN_LENGTH}}", &request.min_length.to_string()),
            ("{{MAX_LENGTH}}", &request.max_length.to_string()),
            ("{{TIMEOUT_SECONDS}}", &ctx.timeout_secs.to_string()),
        ],
    })
}

pub(crate) fn build_code_done_page() -> String {
    build_done_page(DonePage {
        title: "sfae - code received",
        heading: "Code received",
    })
}

pub(crate) fn build_code_cancelled_page() -> String {
    build_done_page(DonePage {
        title: "sfae - code cancelled",
        heading: "Code request cancelled",
    })
}

fn input_mode(format: CodeFormat) -> &'static str {
    match format {
        CodeFormat::Digits => "numeric",
        CodeFormat::Alnum | CodeFormat::Text => "text",
    }
}

struct DonePage<'a> {
    title: &'a str,
    heading: &'a str,
}

fn build_done_page(page: DonePage<'_>) -> String {
    apply_template(Template {
        source: include_str!("done.html"),
        vars: &[
            ("{{BASE_STYLES}}", BASE_STYLES),
            ("{{TITLE}}", page.title),
            ("{{HEADING}}", page.heading),
        ],
    })
}

struct Template<'a> {
    source: &'a str,
    vars: &'a [(&'a str, &'a str)],
}

fn apply_template(tpl: Template<'_>) -> String {
    let mut out = tpl.source.to_string();
    for (key, value) in tpl.vars {
        out = out.replace(key, value);
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::code::{CodeFormat, CodeRequest, DEFAULT_TIMEOUT_SECS};

    fn request() -> CodeRequest {
        CodeRequest {
            domain: "example.com".to_string(),
            label: Some("Work <Admin>".to_string()),
            message: Some("Enter <code> & continue".to_string()),
            help_url: Some("https://example.com/login?next=2fa".to_string()),
            format: CodeFormat::Digits,
            min_length: 6,
            max_length: 6,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    #[test]
    fn code_page_contains_one_time_code_fields() {
        let html = build_code_page(CodePageContext {
            request: &request(),
            csrf_token: "token-123",
            error: None,
            timeout_secs: 300,
        });
        assert!(html.contains(r#"autocomplete="one-time-code""#));
        assert!(html.contains(r#"inputmode="numeric""#));
        assert!(html.contains(r#"name="_code""#));
        assert!(html.contains(r#"name="_csrf""#));
        assert!(html.contains(r#"data-required="true""#));
        assert!(html.contains(r#"data-submit"#));
        assert!(html.contains("sfaeWireSubmitState"));
        assert!(html.contains(r#"class="site-mark""#));
        assert!(html.contains("Cancel"));
        assert!(!html.contains("stored in Passwords"));

        let cancel = html.find("Cancel").expect("cancel button missing");
        let submit = html.find("Submit").expect("submit button missing");
        assert!(cancel < submit);
    }

    #[test]
    fn code_page_escapes_dynamic_text() {
        let html = build_code_page(CodePageContext {
            request: &request(),
            csrf_token: "\"csrf\"",
            error: Some("Bad <code>"),
            timeout_secs: 42,
        });
        assert!(html.contains("Work &lt;Admin&gt;"));
        assert!(html.contains("Enter &lt;code&gt; &amp; continue"));
        assert!(html.contains("&quot;csrf&quot;"));
        assert!(html.contains("Bad &lt;code&gt;"));
        assert!(html.contains(r#"<span id="timer">42</span>"#));
    }
}
