use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Danger,
}

impl ButtonVariant {
    fn classes(self) -> &'static str {
        match self {
            ButtonVariant::Primary => "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500",
            ButtonVariant::Secondary => {
                "bg-white text-slate-700 border border-slate-300 hover:bg-slate-50 focus:ring-slate-400"
            }
            ButtonVariant::Danger => "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500",
        }
    }
}

const BASE: &str = "inline-flex w-full items-center justify-center gap-2 rounded-md px-4 py-2 \
                    text-sm font-medium shadow-sm transition-colors focus:outline-none \
                    focus:ring-2 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

#[component]
pub fn Button(
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] loading: Signal<bool>,
    children: Children,
) -> impl IntoView {
    view! {
        <button
            class=move || format!("{BASE} {}", variant.classes())
            // Disabled while in flight, so a double click cannot submit twice — the
            // previous implementation guarded this in the click handler only, which does
            // nothing for a keyboard-submitted form.
            disabled=move || disabled.get() || loading.get()
        >
            <Show when=move || loading.get()>
                <span class="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
                      aria-hidden="true"/>
            </Show>
            {children()}
        </button>
    }
}
