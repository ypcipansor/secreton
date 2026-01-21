use leptos::prelude::*;

#[component]
pub fn Card(
    #[prop(optional)] title: Option<String>,
    #[prop(optional)] subtitle: Option<String>,
    #[prop(optional, into)] actions: Option<AnyView>,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="bg-white overflow-hidden shadow rounded-lg border border-gray-100">
            {
                if title.is_some() || actions.is_some() {
                    view! {
                        <div class="px-4 py-5 sm:px-6 border-b border-gray-100 flex justify-between items-center">
                            <div>
                                {if let Some(t) = &title {
                                    view! { <h3 class="text-lg leading-6 font-medium text-gray-900">{t.clone()}</h3> }.into_any()
                                } else {
                                    ().into_any()
                                }}
                                {if let Some(s) = &subtitle {
                                    view! { <p class="mt-1 max-w-2xl text-sm text-gray-500">{s.clone()}</p> }.into_any()
                                } else {
                                    ().into_any()
                                }}
                            </div>
                            {
                                if let Some(act) = actions {
                                    view! { <div class="flex-shrink-0">{act}</div> }.into_any()
                                } else {
                                    ().into_any()
                                }
                            }
                        </div>
                    }.into_any()
                } else {
                    ().into_any()
                }
            }
            <div class="px-4 py-5 sm:p-6">
                {children()}
            </div>
        </div>
    }
}
