//! Embedded HTML templates (login, error, home page).
//!
//! Templates are compiled into the binary with `include_str!`. When
//! `login.template_dir` is configured, files with the same name in that
//! directory take precedence, so a project can restyle the login page without
//! rebuilding the server. Templates are reloaded from disk on every render.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use minijinja::{Environment, TemplateSource, UndefinedBehavior};
use serde::Serialize;
use thiserror::Error;

/// Home page and token generator (single HTML file, no external assets).
pub const HOME_HTML: &str = include_str!("../../templates/home.html");
/// Login page (form and picker modes).
pub const LOGIN_HTML: &str = include_str!("../../templates/login.html");
/// Error page shown when a request cannot be redirected back to the client.
pub const ERROR_HTML: &str = include_str!("../../templates/error.html");
/// Authorization code redirect target of the token generator.
pub const CALLBACK_HTML: &str = include_str!("../../templates/callback.html");
/// Page shown after a successful logout when no redirect is registered.
pub const LOGOUT_HTML: &str = include_str!("../../templates/logout.html");

const EMBEDDED: [(&str, &str); 5] = [
    ("home.html", HOME_HTML),
    ("login.html", LOGIN_HTML),
    ("error.html", ERROR_HTML),
    ("callback.html", CALLBACK_HTML),
    ("logout.html", LOGOUT_HTML),
];

fn embedded(name: &str) -> Option<&'static str> {
    EMBEDDED
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, source)| *source)
}

#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("failed to render template '{name}': {message}")]
    Render { name: String, message: String },
}

/// Template environment shared by the HTTP handlers.
pub struct Templates {
    env: Environment<'static>,
}

impl std::fmt::Debug for Templates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Templates").finish_non_exhaustive()
    }
}

impl Templates {
    /// Builds the environment, optionally with a directory that overrides the
    /// embedded templates.
    pub fn load(template_dir: Option<&Path>) -> Arc<Self> {
        let dir: Option<PathBuf> = template_dir.map(Path::to_path_buf);

        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Lenient);
        // Templates on disk change without restarting the server.
        env.set_auto_reload(true);
        env.set_loader(move |name| {
            if let Some(dir) = &dir {
                let path = dir.join(name);
                if path.is_file() {
                    let source = std::fs::read_to_string(&path).map_err(|err| {
                        minijinja::Error::new(
                            minijinja::ErrorKind::InvalidOperation,
                            format!("cannot read template '{}': {err}", path.display()),
                        )
                    })?;
                    return Ok(Some(TemplateSource::new(source)));
                }
            }
            Ok(embedded(name).map(TemplateSource::new))
        });

        Arc::new(Self { env })
    }

    /// Renders `name` with `context`; `name` must be one of `home.html`,
    /// `login.html` or `error.html`.
    pub fn render(&self, name: &str, context: &impl Serialize) -> Result<String, TemplateError> {
        let context = minijinja::value::Value::from(minijinja::value::Serde(context));
        self.env
            .get_template(name)
            .and_then(|template| template.render(&context))
            .map_err(|err| TemplateError::Render {
                name: name.to_string(),
                message: err.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn embedded_templates_are_available() {
        let templates = Templates::load(None);
        let html = templates
            .render(
                "login.html",
                &json!({
                    "mode": "form",
                    "client_id": "my-spa",
                    "users": [],
                    "error": null,
                    "return_to": "/authorize?client_id=my-spa",
                }),
            )
            .unwrap();
        assert!(html.contains("my-spa"));
        assert!(html.contains("<form"));
        assert!(!html.contains("<script src="));
    }

    #[test]
    fn home_template_renders_without_leaking_syntax() {
        let templates = Templates::load(None);
        let html = templates
            .render("home.html", &json!({ "version": "0.1.0" }))
            .unwrap();
        assert!(html.contains("Token generator"));
        assert!(html.contains("v0.1.0"));
        assert!(
            !html.contains("{{"),
            "unrendered template syntax left: {html}"
        );
        assert!(!html.contains("<script src="));
    }

    #[test]
    fn error_template_escapes_values() {
        let templates = Templates::load(None);
        let html = templates
            .render(
                "error.html",
                &json!({
                    "error": "invalid_request",
                    "description": "<script>alert(1)</script>",
                }),
            )
            .unwrap();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn directory_templates_take_precedence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("error.html"),
            "<p>custom error: {{ description }}</p>",
        )
        .unwrap();

        let templates = Templates::load(Some(dir.path()));
        let html = templates
            .render(
                "error.html",
                &json!({ "error": "x", "description": "boom" }),
            )
            .unwrap();
        assert_eq!(html.trim(), "<p>custom error: boom</p>");

        // Templates without an override still come from the binary.
        let login = templates
            .render(
                "login.html",
                &json!({ "mode": "form", "client_id": "c", "users": [], "error": null, "return_to": "/" }),
            )
            .unwrap();
        assert!(login.contains("<form"));
    }
}
