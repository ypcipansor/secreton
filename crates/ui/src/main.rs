mod api;
mod auth;
mod app;
mod pages;
mod components;

use leptos::prelude::*;

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    console_error_panic_hook::set_once();

    mount_to_body(|| {
        view! { <app::App/> }
    });
}
