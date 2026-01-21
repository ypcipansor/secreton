use leptos::prelude::*;
use leptos::task::spawn_local;
use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::input::Input;
use crate::components::card::Card;
use crate::components::modal::Modal;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UserResponse {
    id: String,
    username: String,
    email: String,
    full_name: Option<String>,
    roles: Vec<String>,
    enabled: bool,
    last_login: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    password: Option<String>,
    full_name: Option<String>,
    enabled: bool,
    roles: Vec<String>,
    permissions: Vec<String>,
}

#[component]
pub fn UsersList() -> impl IntoView {
    // Resource
    let users_resource = LocalResource::new(|| async move {
        api::get::<Vec<UserResponse>>("/users").await
    });

    // State
    let (show_modal, set_show_modal) = signal(false);
    let (username, set_username) = signal("".to_string());
    let (email, set_email) = signal("".to_string());
    let (password, set_password) = signal("".to_string());
    let (full_name, set_full_name) = signal("".to_string());
    let (roles_str, set_roles_str) = signal("".to_string());

    let open_create = move |_| {
        set_username.set("".to_string());
        set_email.set("".to_string());
        set_password.set("".to_string());
        set_full_name.set("".to_string());
        set_roles_str.set("".to_string());
        set_show_modal.set(true);
    };

    let handle_create = move || {
        spawn_local(async move {
            let roles: Vec<String> = roles_str.get()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let req = CreateUserRequest {
                username: username.get(),
                email: email.get(),
                password: if password.get().is_empty() { None } else { Some(password.get()) },
                full_name: if full_name.get().is_empty() { None } else { Some(full_name.get()) },
                enabled: true,
                roles,
                permissions: vec![],
            };

            if let Ok(_) = api::post::<serde_json::Value, _>("/users", req).await {
                set_show_modal.set(false);
                users_resource.refetch();
            }
        });
    };

    let handle_delete = move |id: String| {
        if !web_sys::window().unwrap().confirm_with_message("Delete user?").unwrap_or(false) {
            return;
        }
        spawn_local(async move {
            let url = format!("/users/{}", id);
            let _ = api::delete::<serde_json::Value>(&url).await;
            users_resource.refetch();
        });
    };

    view! {
        <div class="space-y-6">
             <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"Users"</h1>
                    <p class="text-gray-500 text-sm mt-1">"Manage system users and access."</p>
                </div>
                <Button variant=ButtonVariant::Primary on_click=Box::new(open_create)>
                    "Create User"
                </Button>
            </header>

            <Suspense fallback=|| view! { <div class="text-center p-8">"Loading users..."</div> }>
                {move || {
                    users_resource.get().map(|res| {
                        match res {
                            Ok(users) => {
                                if users.is_empty() {
                                     view! {
                                        <Card>
                                            <div class="text-center py-8 text-gray-500">"No users found."</div>
                                        </Card>
                                     }.into_any()
                                } else {
                                     view! {
                                        <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                                            {users.into_iter().map(|user| {
                                                let u_del = user.id.clone();
                                                let subtitle = user.full_name.unwrap_or_else(|| user.email.clone());

                                                view! {
                                                    <Card
                                                        title=user.username.clone()
                                                        subtitle=subtitle
                                                        actions=view! {
                                                            <button
                                                                class="text-red-600 hover:text-red-800 text-sm font-medium"
                                                                on:click=move |_| handle_delete(u_del.clone())
                                                            >
                                                                "Delete"
                                                            </button>
                                                        }.into_any()
                                                    >
                                                        <div class="mt-2 space-y-2">
                                                            <div class="flex flex-wrap gap-2">
                                                                {user.roles.iter().map(|r| view! {
                                                                    <span class="px-2 py-0.5 rounded-full text-xs bg-purple-100 text-purple-800 font-medium">
                                                                        {r.clone()}
                                                                    </span>
                                                                }).collect_view()}
                                                            </div>
                                                            <div class="text-xs text-gray-400 pt-2 border-t border-gray-100">
                                                                "Last Login: " {user.last_login.unwrap_or("Never".to_string())}
                                                            </div>
                                                        </div>
                                                    </Card>
                                                }
                                            }).collect_view()}
                                        </div>
                                     }.into_any()
                                }
                            },
                            Err(e) => view! {
                                <div class="bg-red-50 text-red-700 p-4 rounded border border-red-200">
                                    "Error loading users: " {e.to_string()}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>

            <Modal
                show=show_modal
                on_close=move || set_show_modal.set(false)
                title="Create New User".to_string()
            >
                <div class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <Input label="Username".to_string() value=username on_input=Box::new(move |v| set_username.set(v)) />
                        <Input label="Full Name".to_string() value=full_name on_input=Box::new(move |v| set_full_name.set(v)) />
                    </div>

                    <Input label="Email".to_string() value=email on_input=Box::new(move |v| set_email.set(v)) type_="email".to_string() />

                    <Input label="Password".to_string() value=password on_input=Box::new(move |v| set_password.set(v)) type_="password".to_string() />

                    <Input label="Roles (comma separated)".to_string() placeholder="admin, editor".to_string() value=roles_str on_input=Box::new(move |v| set_roles_str.set(v)) />

                    <div class="flex justify-end pt-4">
                        <Button variant=ButtonVariant::Primary on_click=Box::new(move |_| handle_create())>
                            "Create User"
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
