use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Default)]
pub enum ButtonVariant {
    #[default]
    Primary,
    #[allow(dead_code)]
    Secondary,
    Danger,
    Outline,
}

#[component]
pub fn Button(
    #[prop(optional, into)] variant: ButtonVariant,
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] loading: Signal<bool>,
    #[prop(optional)] on_click: Option<Box<dyn Fn(leptos::ev::MouseEvent) + Send + Sync>>,
    #[prop(optional)] type_: &'static str,
    children: Children,
) -> impl IntoView {
    let base_class = "inline-flex items-center justify-center px-4 py-2 border text-sm font-medium rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200";

    let variant_class = move || match variant {
        ButtonVariant::Primary => {
            "border-transparent text-white bg-blue-600 hover:bg-blue-700 focus:ring-blue-500"
        }
        ButtonVariant::Secondary => {
            "border-transparent text-blue-700 bg-blue-100 hover:bg-blue-200 focus:ring-blue-500"
        }
        ButtonVariant::Danger => {
            "border-transparent text-white bg-red-600 hover:bg-red-700 focus:ring-red-500"
        }
        ButtonVariant::Outline => {
            "border-gray-300 text-gray-700 bg-white hover:bg-gray-50 focus:ring-blue-500"
        }
    };

    let on_click_handler = move |ev: leptos::ev::MouseEvent| {
        if !disabled.get() && !loading.get() {
            if let Some(cb) = &on_click {
                cb(ev);
            }
        }
    };

    view! {
        <button
            type=if type_.is_empty() { "button" } else { type_ }
            class=move || format!("{} {} {}", base_class, variant_class(), class)
            disabled=move || disabled.get() || loading.get()
            on:click=on_click_handler
        >
            <Show when=move || loading.get() fallback=|| ()>
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-current" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            </Show>
            {children()}
        </button>
    }
}
