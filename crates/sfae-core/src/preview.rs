//! Developer-only HTML rendering helpers for visual preview tooling.
//!
//! These functions expose the production credential and code page renderers
//! without starting browser prompts, OAuth sessions, or credential storage.

use crate::browser::FormContext;
use crate::code::CodeRequest;
use crate::code_html::{
    CodePageContext, build_code_cancelled_page, build_code_done_page, build_code_page,
};

/// Inputs for rendering a one-time-code page preview.
pub struct CodePreview<'a> {
    /// Code request whose user-facing fields should be rendered.
    pub request: &'a CodeRequest,
    /// Synthetic CSRF token used only by the preview page markup.
    pub csrf_token: &'a str,
    /// Optional validation error to display above the code input.
    pub error: Option<&'a str>,
    /// Remaining seconds displayed in the countdown.
    pub timeout_secs: u64,
}

/// Render the spec-driven credential form using the production template.
pub fn render_form_page(ctx: FormContext<'_>) -> String {
    crate::browser_html::build_form_page(ctx)
}

/// Render the credential completion page using the production template.
pub fn render_credential_done_page() -> String {
    crate::browser_html::build_done_page()
}

/// Render the one-time-code form using the production template.
pub fn render_code_page(ctx: CodePreview<'_>) -> String {
    build_code_page(CodePageContext {
        request: ctx.request,
        csrf_token: ctx.csrf_token,
        error: ctx.error,
        timeout_secs: ctx.timeout_secs,
    })
}

/// Render the one-time-code completion page using the production template.
pub fn render_code_done_page() -> String {
    build_code_done_page()
}

/// Render the one-time-code cancellation page using the production template.
pub fn render_code_cancelled_page() -> String {
    build_code_cancelled_page()
}
