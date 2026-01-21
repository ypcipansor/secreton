use leptos::prelude::*;

#[component]
pub fn Input(
    #[prop(optional, into)] id: String,
    #[prop(optional, into)] type_: String,
    #[prop(optional, into)] label: String,
    #[prop(optional, into)] placeholder: String,
    #[prop(optional, into)] value: Signal<String>,
    #[prop(optional, into)] error: Signal<Option<String>>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional)] on_input: Option<Box<dyn Fn(String) + Send + Sync>>,
) -> impl IntoView {
    let type_val = if type_.is_empty() { "text".to_string() } else { type_ };

    let on_input_handler = move |ev: leptos::ev::Event| {
        let val = event_target_value(&ev);
        if let Some(cb) = &on_input {
            cb(val);
        }
    };

    // Clone for usage in closures
    let label_for_show = label.clone();
    let label_for_text = label.clone();
    let id_for_label = id.clone();
    let id_for_input = id.clone();

    view! {
        <div class="space-y-1">
            <Show when=move || !label_for_show.is_empty()>
                <label for=id_for_label.clone() class="block text-sm font-medium text-gray-700">
                    {label_for_text.clone()}
                </label>
            </Show>
            <div class="relative rounded-md shadow-sm">
                <input
                    type=type_val
                    id=if id_for_input.is_empty() { None } else { Some(id_for_input) }
                    class=move || {
                        let base = "block w-full px-3 py-2 sm:text-sm rounded-md shadow-sm outline-none transition-colors";
                        let border = if error.get().is_some() {
                            "border-red-300 text-red-900 placeholder-red-300 focus:ring-red-500 focus:border-red-500 border"
                        } else {
                            "border-gray-300 placeholder-gray-400 focus:ring-blue-500 focus:border-blue-500 border"
                        };
                        format!("{} {}", base, border)
                    }
                    placeholder=placeholder
                    prop:value=value
                    disabled=move || disabled.get()
                    on:input=on_input_handler
                />
            </div>
            <Show when=move || error.get().is_some()>
                <p class="mt-1 text-sm text-red-600">
                    {move || error.get().unwrap()}
                </p>
            </Show>
        </div>
    }
}
