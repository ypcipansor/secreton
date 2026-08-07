use leptos::prelude::*;

/// A labelled text input.
///
/// `name` is passed through to the underlying `<input>` so the component works inside an
/// `ActionForm`, which serialises the form by field name. That is what lets login submit
/// without JavaScript when the WebAssembly bundle has not loaded yet.
#[component]
pub fn Input(
    #[prop(into)] name: String,
    #[prop(into)] label: String,
    #[prop(into, default = "text".to_string())] input_type: String,
    #[prop(into, optional)] autocomplete: String,
    #[prop(default = false)] required: bool,
) -> impl IntoView {
    let id = format!("field-{}", name.replace(['[', ']'], "-"));
    view! {
        <div class="space-y-1">
            <label for=id.clone() class="block text-sm font-medium text-slate-700">{label}</label>
            <input
                id=id
                name=name
                type=input_type
                autocomplete=autocomplete
                required=required
                class="w-full rounded-md border border-slate-300 px-3 py-2 text-sm \
                       focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
        </div>
    }
}
