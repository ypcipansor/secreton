//! The Content-Security-Policy text.
//!
//! The policy lives here, in the crate that has no web framework, because two sides need
//! to agree on it exactly: the server's header middleware, which sets the policy on every
//! response, and the UI shell, which raises the rendered document's nonce so the policy can
//! name it. A policy assembled independently in two crates is a policy that drifts, and a
//! policy whose nonce does not match the document silently kills every inline script.

/// The policy with `{nonce}` as the substitution point for a document's nonce.
///
/// `wasm-unsafe-eval` is required: instantiating a WebAssembly module counts as eval, and
/// the Leptos client bundle is WASM. `'unsafe-inline'` for styles is required by Leptos'
/// hydration, which emits inline style attributes.
///
/// The `script-src` nonce is what lets the inline scripts Leptos writes run. Without it the
/// page renders but never hydrates: those scripts boot the WASM bundle and open the
/// hydration stream, so every control stays inert and a filled-in login form will not even
/// submit. Naming the nonce is strictly better than adding `'unsafe-inline'`, which would
/// also admit an injected script.
pub const CSP_TEMPLATE: &str = "default-src 'self'; \
     script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     font-src 'self'; \
     connect-src 'self'; \
     object-src 'none'; \
     base-uri 'none'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// The policy for a rendered document, naming the nonce its inline scripts carry.
pub fn csp_with_nonce(nonce: &str) -> String {
    CSP_TEMPLATE.replace("{nonce}", nonce)
}

/// The policy for a response that embeds no scripts: API JSON, static files and errors.
/// No nonce is issued because there is nothing to authorise.
pub fn csp_without_nonce() -> String {
    CSP_TEMPLATE.replace("'nonce-{nonce}' ", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonced_policy_names_that_nonce_and_still_allows_wasm() {
        let policy = csp_with_nonce("abc123");
        assert!(policy.contains("'nonce-abc123'"), "{policy}");
        assert!(policy.contains("'wasm-unsafe-eval'"), "{policy}");
        assert!(!policy.contains("{nonce}"), "{policy}");
    }

    #[test]
    fn a_nonced_policy_does_not_admit_arbitrary_inline_script() {
        let policy = csp_with_nonce("abc123");
        assert!(
            !policy.contains("script-src 'self' 'unsafe-inline'"),
            "inline script must be admitted only through the nonce: {policy}"
        );
    }

    #[test]
    fn a_documentless_policy_carries_no_nonce() {
        let policy = csp_without_nonce();
        assert!(!policy.contains("nonce-"), "{policy}");
        assert!(!policy.contains("{nonce}"), "{policy}");
        assert!(
            policy.contains("script-src 'self' 'wasm-unsafe-eval'"),
            "{policy}"
        );
    }

    #[test]
    fn the_hardening_directives_survive_substitution() {
        for policy in [csp_with_nonce("n"), csp_without_nonce()] {
            for directive in [
                "frame-ancestors 'none'",
                "object-src 'none'",
                "base-uri 'none'",
                "form-action 'self'",
            ] {
                assert!(
                    policy.contains(directive),
                    "missing {directive} in {policy}"
                );
            }
        }
    }
}
