use leptos::*;

#[component]
pub fn PoliciesList() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <header class="flex justify-between items-center">
                <h1 class="text-3xl font-bold text-gray-900">"Policies"</h1>
                <button class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">"Create Policy"</button>
            </header>

            <div class="bg-white rounded-lg shadow overflow-hidden">
                <div class="p-6 text-center text-gray-500">
                    <p>"Policy management coming soon."</p>
                    <p class="text-sm mt-2">"This feature is under development."</p>
                </div>
            </div>
        </div>
    }
}
