use crate::components::button::{Button, ButtonVariant};
use leptos::prelude::*;

#[component]
pub fn Modal(
    #[prop(into)] show: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(optional, into)] title: String,
    children: ChildrenFn,
) -> impl IntoView {
    view! {
        {move || if show.get() {
            view! {
                <div class="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
                    <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
                        // Background overlay
                        <div
                            class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
                            aria-hidden="true"
                            on:click=move |_| on_close.run(())
                        ></div>

                        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">"&#8203;"</span>

                        // Modal panel
                        <div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
                            <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                                <div class="sm:flex sm:items-start">
                                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                                        <h3 class="text-lg leading-6 font-medium text-gray-900" id="modal-title">
                                            {title.clone()}
                                        </h3>
                                        <div class="mt-2">
                                            {children()}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                                <Button
                                    variant=ButtonVariant::Outline
                                    on_click=Box::new(move |_| on_close.run(()))
                                >
                                    "Close"
                                </Button>
                            </div>
                        </div>
                    </div>
                </div>
            }.into_any()
        } else {
            ().into_any()
        }}
    }
}
