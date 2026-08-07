use leptos::prelude::*;

use crate::api::system_status;
use crate::components::Card;

#[component]
pub fn Dashboard() -> impl IntoView {
    // `Resource`, not `LocalResource`: this is fetched during server rendering and
    // serialised into the page, so the first paint already carries the data. The previous
    // version used a client-only resource, so every visitor saw an empty shell first.
    let status = Resource::new(|| (), |_| async move { system_status().await });

    view! {
        <div class="space-y-6">
            <header>
                <h1 class="text-2xl font-semibold">"Dashboard"</h1>
                <p class="text-sm text-slate-500">"System status at a glance"</p>
            </header>

            <Suspense fallback=|| view! {
                <p class="text-sm text-slate-500">"Loading status…"</p>
            }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(s) => view! {
                            <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                                <Card title="Seal">
                                    <span class=move || if s.sealed {
                                        "text-red-600 font-medium"
                                    } else {
                                        "text-emerald-600 font-medium"
                                    }>
                                        {if s.sealed { "Sealed" } else { "Unsealed" }}
                                    </span>
                                </Card>
                                <Card title="Secrets">{s.secret_count.to_string()}</Card>
                                <Card title="Storage">{s.storage_backend.clone()}</Card>
                                <Card title="Version">{s.version.clone()}</Card>
                            </div>
                        }.into_any(),
                        Err(e) => view! {
                            <p role="alert" class="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                                {format!("Could not load status: {e}")}
                            </p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}
