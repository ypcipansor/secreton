use leptos::prelude::*;

#[component]
pub fn Card(#[prop(into)] title: String, children: Children) -> impl IntoView {
    view! {
        <section class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
            <h2 class="text-xs font-medium uppercase tracking-wide text-slate-500">{title}</h2>
            <div class="mt-2 text-lg">{children()}</div>
        </section>
    }
}
