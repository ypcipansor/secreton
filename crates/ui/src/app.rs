//! Application shell and routing.

use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{ParentRoute, Route, Router, Routes};
use leptos_router::{StaticSegment, path};

use crate::auth::{provide_session, use_session};
use crate::components::Layout;
use crate::pages::{dashboard::Dashboard, login::Login, not_found::NotFound};

/// The HTML document. Rendered on the server, hydrated in the browser.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body class="bg-slate-50 text-slate-900 antialiased">
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    provide_session();

    view! {
        // Tailwind is compiled locally by cargo-leptos into this file. It used to be
        // fetched from cdn.tailwindcss.com at runtime: a build tool never meant for
        // production, and a third-party script with full DOM access on pages that
        // render secrets.
        <Stylesheet id="leptos" href="/pkg/secreton.css"/>
        <Title text="Secreton"/>

        <Router>
            <Routes fallback=NotFound>
                <Route path=StaticSegment("login") view=Login/>
                <ParentRoute path=path!("/") view=Protected>
                    <Route path=path!("") view=Dashboard/>
                </ParentRoute>
            </Routes>
        </Router>
    }
}

/// Gate for routes that need a session.
///
/// This is a convenience for the visitor, not a security boundary: the real check is
/// server-side, in the auth middleware and in every server function. A page that relied on
/// this alone would be bypassable by calling the endpoint directly.
#[component]
fn Protected() -> impl IntoView {
    use leptos_router::components::{Outlet, Redirect};

    let session = use_session();

    view! {
        <Suspense fallback=|| view! {
            <div class="flex h-screen items-center justify-center text-slate-500">"Loading…"</div>
        }>
            {move || {
                if session.is_authenticated() {
                    view! { <Layout><Outlet/></Layout> }.into_any()
                } else {
                    view! { <Redirect path="/login"/> }.into_any()
                }
            }}
        </Suspense>
    }
}
