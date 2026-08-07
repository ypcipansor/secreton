//! Session state in the UI.
//!
//! The browser holds no token. It holds only who the server said is signed in; the
//! credential itself lives in an `HttpOnly` cookie the page cannot read. That is the whole
//! point of the change — the previous version kept a JWT in `localStorage`, one XSS away
//! from every secret in the system.

use leptos::prelude::*;

use crate::api::{SessionUser, current_session};

/// Resource resolving the current session, shared through context.
///
/// `Resource` rather than `LocalResource`: it is fetched during server rendering and
/// serialised into the page, so the first paint already knows whether the visitor is
/// signed in. A client-only resource would render a logged-out shell and then flip.
#[derive(Clone, Copy)]
pub struct SessionContext(pub Resource<Result<Option<SessionUser>, ServerFnError>>);

pub fn provide_session() -> SessionContext {
    let resource = Resource::new(|| (), |_| async move { current_session().await });
    let ctx = SessionContext(resource);
    provide_context(ctx);
    ctx
}

pub fn use_session() -> SessionContext {
    use_context::<SessionContext>()
        .expect("provide_session() must be called before use_session(); see app::App")
}

impl SessionContext {
    /// The signed-in user, or `None` while loading or when signed out.
    pub fn user(&self) -> Option<SessionUser> {
        self.0.get().and_then(|r| r.ok()).flatten()
    }

    pub fn is_authenticated(&self) -> bool {
        self.user().is_some()
    }

    /// Re-run the session lookup, e.g. after login or logout.
    pub fn refetch(&self) {
        self.0.refetch();
    }
}
