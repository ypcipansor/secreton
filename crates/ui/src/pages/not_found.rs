use leptos::prelude::*;

#[component]
pub fn NotFound() -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center min-h-[50vh] text-center">
            <h1 class="text-6xl font-bold text-gray-200">"404"</h1>
            <p class="text-xl text-gray-600 mt-4">"Page not found"</p>
            <a href="/" class="mt-8 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition">
                "Go Home"
            </a>
        </div>
    }
}
