use leptos::prelude::*;
use leptos::task::spawn_local;
use crate::api;
use crate::components::card::Card;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub enabled: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub last_login: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: HashMap<String, String>,
}

#[component]
pub fn UsersList() -> impl IntoView {
    let users_resource = LocalResource::new(
        move || async move {
            api::get::<Vec<UserResponse>>("/admin/users").await
        },
    );

    let (delete_error, set_delete_error) = signal(None::<String>);

    let handle_delete = move |id: String, username: String| {
        let Some(window) = web_sys::window() else { return };
        if !window.confirm_with_message(&format!("Delete user {}?", username)).unwrap_or(false) {
            return;
        }
        set_delete_error.set(None);
        spawn_local(async move {
            let url = format!("/admin/users/{}", id);
            match api::delete::<serde_json::Value>(&url).await {
                Ok(_) => {
                    users_resource.refetch();
                }
                Err(e) => {
                    set_delete_error.set(Some(format!("Failed to delete user {}: {}", username, e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-6">
            <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"User Management"</h1>
                    <p class="text-gray-500 text-sm mt-1">"Manage system users and their access"</p>
                </div>
            </header>

            {move || {
                delete_error.get().map(|err| view! {
                    <div class="p-4 bg-red-50 text-red-700 rounded border border-red-200">
                        {err}
                    </div>
                })
            }}

            <Suspense fallback=|| view! { <div class="text-center p-8">"Loading users..."</div> }>
                {move || {
                    users_resource.get().map(|res| {
                        match res {
                            Ok(users) => {
                                let users = users.clone();
                                if users.is_empty() {
                                    view! {
                                        <Card>
                                            <div class="text-center py-8 text-gray-500">
                                                "No users found."
                                            </div>
                                        </Card>
                                    }.into_any()
                                } else {
                                    view! {
                                        <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                                            {users.into_iter().map(|user| {
                                                let u_id = user.id.clone();
                                                let u_name = user.username.clone();
                                                let u_del_id = user.id.clone();
                                                let u_del_name = user.username.clone();
                                                let u_email = user.email.clone();
                                                let u_enabled = user.enabled;

                                                view! {
                                                    <Card
                                                        title=u_name.clone()
                                                        subtitle=u_email
                                                        actions=view! {
                                                            <button
                                                                class="text-red-600 hover:text-red-800 text-sm font-medium"
                                                                on:click=move |_| handle_delete(u_del_id.clone(), u_del_name.clone())
                                                            >
                                                                "Delete"
                                                            </button>
                                                        }.into_any()
                                                    >
                                                        <div class="mt-2 space-y-3">
                                                            <div>
                                                                <h4 class="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">"Roles"</h4>
                                                                <div class="flex flex-wrap gap-1">
                                                                    {user.roles.iter().map(|r| view! {
                                                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                                                                            {r.clone()}
                                                                        </span>
                                                                    }).collect_view()}
                                                                </div>
                                                            </div>
                                                            <div class="flex justify-between items-center text-xs">
                                                                <span class="text-gray-500">"Status"</span>
                                                                <span class={if u_enabled { "text-green-600 font-medium" } else { "text-red-600 font-medium" }}>
                                                                    {if u_enabled { "Enabled" } else { "Disabled" }}
                                                                </span>
                                                            </div>
                                                            <div class="flex justify-between items-center text-xs">
                                                                <span class="text-gray-500">"Created"</span>
                                                                <span class="text-gray-900">{user.created_at.split('T').next().unwrap_or_default().to_string()}</span>
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
                                <div class="p-4 bg-red-50 text-red-700 rounded border border-red-200">
                                    "Error loading users: " {e.to_string()}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
