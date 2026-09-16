//! The browser session cookie.
//!
//! This lives in `secreton-domain` because both halves of the application need it and
//! neither can depend on the other: the Axum middleware in `secreton-server` reads the
//! cookie, and the Leptos server functions in `secreton-ui` set and clear it. `server`
//! depends on `ui`, so there is no crate above both — the shared definition has to sit
//! below both, here.
//!
//! It previously did not. `secreton-server` held a well-tested pair of builders that
//! nothing called, and `secreton-ui` hand-rolled the header with `format!` and its own
//! copy of the cookie name. The two drifted, in exactly the way the dead version's own
//! test warned about: the live clearing header omitted `Secure` while the live setting
//! header added it. Browsers key cookies by name, domain and path — `Secure` is not part
//! of that key — so same-scheme deletion still worked, which is why nothing caught it.
//!
//! The attributes are now built once, by a single private helper, and shared by the
//! setting and clearing headers. Divergence is no longer something to remember: it is
//! unrepresentable.
//!
//! Returned values are `Set-Cookie` header *values*, deliberately plain `String`s: this
//! crate compiles for `wasm32-unknown-unknown` and must not pull in a web framework.

use crate::{Result, SecretonError};

/// Name of the cookie carrying a browser session token.
pub const SESSION_COOKIE: &str = "secreton_session";

/// Attributes shared by the setting and clearing headers.
///
/// Every attribute that identifies the cookie to a browser, or that a clearing header must
/// repeat, belongs here rather than in either caller. `Max-Age` is the one attribute that
/// legitimately differs, so it stays with the callers.
///
/// - `HttpOnly` — unreachable from JavaScript, so an XSS cannot read the session out of a
///   page whose whole purpose is holding secrets. This is why the token is not in
///   `localStorage`, where the UI used to keep it.
/// - `SameSite=Lax` — not attached to cross-site POSTs, which blocks the basic CSRF shape.
/// - `Path=/` — one scope for the whole application.
/// - `Secure` — only when asserted by the caller. Setting it unconditionally makes login
///   silently fail over plain `http://localhost`, because the browser drops the cookie
///   without telling the page.
fn attributes(secure: bool) -> &'static str {
    if secure {
        "; HttpOnly; SameSite=Lax; Path=/; Secure"
    } else {
        "; HttpOnly; SameSite=Lax; Path=/"
    }
}

/// Reject a token that could not be carried in a cookie value.
///
/// The token comes from this application's own issuer and a JWT cannot contain any of
/// these, so this should never fire. It is here because "cannot happen" is the assumption
/// this codebase has been most often wrong about, and the consequence here is specific: a
/// `;` would smuggle an extra cookie attribute into the header, and a control character
/// would attempt header injection.
fn ensure_cookie_safe(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(SecretonError::Validation {
            message: "session token is empty".to_string(),
        });
    }
    if let Some(bad) = token
        .chars()
        .find(|c| c.is_control() || c.is_whitespace() || matches!(c, ';' | ',' | '"' | '\\'))
    {
        return Err(SecretonError::Validation {
            message: format!("session token contains {bad:?}, which cannot appear in a cookie"),
        });
    }
    Ok(())
}

/// The `Set-Cookie` value that establishes a session.
///
/// `secure` should be false only when serving plain HTTP in local development.
pub fn session_cookie(token: &str, ttl_seconds: i64, secure: bool) -> Result<String> {
    ensure_cookie_safe(token)?;
    Ok(format!(
        "{SESSION_COOKIE}={token}; Max-Age={ttl_seconds}{}",
        attributes(secure)
    ))
}

/// The `Set-Cookie` value that clears a session on logout.
///
/// `secure` must match what [`session_cookie`] was called with, which is why both take it
/// and both read their remaining attributes from the same place.
pub fn clearing_cookie(secure: bool) -> String {
    format!("{SESSION_COOKIE}=; Max-Age=0{}", attributes(secure))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Attributes after the `name=value` pair, which is the part that must match between
    /// setting and clearing.
    fn attrs_of(header: &str) -> Vec<&str> {
        header
            .split(';')
            .skip(1)
            .map(str::trim)
            .filter(|a| !a.starts_with("Max-Age"))
            .collect()
    }

    #[test]
    fn a_session_cookie_is_unreadable_from_script_and_scoped_to_the_site() {
        let header = session_cookie("tok", 3600, true).expect("valid token");
        assert!(header.starts_with("secreton_session=tok;"));
        assert!(header.contains("; HttpOnly"), "got {header}");
        assert!(header.contains("; Secure"), "got {header}");
        assert!(header.contains("; SameSite=Lax"), "got {header}");
        assert!(header.contains("; Path=/"), "got {header}");
        assert!(header.contains("; Max-Age=3600"), "got {header}");
    }

    /// The invariant the previous arrangement broke.
    ///
    /// A clearing header whose attributes differ from the setting header is a header the
    /// browser may not match against the cookie it is meant to remove. The old
    /// `secreton-server` version tested this and was never called; the `secreton-ui`
    /// version was called and never tested, and omitted `Secure`.
    #[test]
    fn the_clearing_cookie_matches_the_session_cookie_attributes() {
        for secure in [true, false] {
            let set = session_cookie("tok", 3600, secure).expect("valid token");
            let clear = clearing_cookie(secure);

            assert_eq!(
                attrs_of(&set),
                attrs_of(&clear),
                "setting and clearing headers disagree at secure={secure}"
            );
            assert!(clear.starts_with("secreton_session=;"), "got {clear}");
            assert!(clear.contains("; Max-Age=0"), "got {clear}");
        }
    }

    #[test]
    fn secure_can_be_relaxed_for_local_http_development() {
        let header = session_cookie("t", 60, false).expect("valid token");
        assert!(!header.contains("Secure"), "got {header}");
        assert!(!clearing_cookie(false).contains("Secure"));
    }

    #[test]
    fn a_token_that_would_smuggle_an_attribute_is_rejected() {
        // Without this, the trailing attribute would ride along in the header and could
        // widen the cookie's scope or drop `HttpOnly`.
        let err = session_cookie("tok; Path=/admin", 60, true);
        assert!(err.is_err(), "a token containing ';' must not be accepted");
    }

    #[test]
    fn a_token_with_a_newline_is_rejected() {
        assert!(session_cookie("tok\r\nX-Evil: 1", 60, true).is_err());
        assert!(session_cookie("", 60, true).is_err(), "empty token");
    }

    /// A realistic JWT must survive the check, or the guard above breaks every login.
    #[test]
    fn a_normal_jwt_is_accepted() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MX0.\
                   3sT-_9xNq0mBk1yQxSb-VbEHY0dQ8pOoJ1s2vXzKQ4w";
        assert!(session_cookie(jwt, 3600, true).is_ok());
    }
}
