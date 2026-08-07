//! Browser session cookies.
//!
//! The UI previously kept its JWT in `localStorage`, where any injected script can read
//! it — in an application whose entire purpose is holding secrets. The token now lives in
//! a cookie the page cannot read:
//!
//! - `HttpOnly` — unreachable from JavaScript, so an XSS cannot exfiltrate the session
//! - `Secure` — never sent over plain HTTP (relaxed only for local development)
//! - `SameSite=Lax` — not attached to cross-site POSTs, which blocks the basic CSRF shape
//! - `Path=/` with an explicit `Max-Age` matching the token's own lifetime
//!
//! Programmatic clients are unaffected and keep using `Authorization: Bearer`.

use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

pub const SESSION_COOKIE: &str = "secreton_session";

/// Build the `Set-Cookie` for a newly issued session.
///
/// `secure` should be false only when serving plain HTTP in local development: a `Secure`
/// cookie is silently dropped by the browser over `http://`, which looks exactly like a
/// broken login.
pub fn session_cookie(token: String, ttl_seconds: i64, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(ttl_seconds))
        .build()
}

/// Build the `Set-Cookie` that clears a session on logout.
///
/// The attributes must match the ones used when setting it, or the browser treats this as
/// a different cookie and leaves the original in place.
pub fn clearing_cookie(secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, ""))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(0))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_cookie_is_unreadable_from_script_and_scoped_to_the_site() {
        let cookie = session_cookie("tok".into(), 3600, true);
        assert_eq!(
            cookie.http_only(),
            Some(true),
            "a session readable from JavaScript defeats the point of moving it out of localStorage"
        );
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(Duration::seconds(3600)));
    }

    #[test]
    fn the_clearing_cookie_matches_the_session_cookie_attributes() {
        let set = session_cookie("tok".into(), 3600, true);
        let clear = clearing_cookie(true);

        // A mismatch on any of these makes the browser keep the original cookie, so
        // "logout" would leave a live session behind.
        assert_eq!(set.name(), clear.name());
        assert_eq!(set.path(), clear.path());
        assert_eq!(set.secure(), clear.secure());
        assert_eq!(set.same_site(), clear.same_site());
        assert_eq!(set.http_only(), clear.http_only());
        assert_eq!(clear.value(), "");
        assert_eq!(clear.max_age(), Some(Duration::seconds(0)));
    }

    #[test]
    fn secure_can_be_relaxed_for_local_http_development() {
        assert_eq!(session_cookie("t".into(), 60, false).secure(), Some(false));
    }
}
