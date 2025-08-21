use leptos::*;

#[component]
pub fn Admin(cx: Scope) -> impl IntoView {
    view! { cx,
        <h2>"Admin"</h2>
        <h3>"Add Role"</h3>
        <form>
            <input type="text" placeholder="Role name" />
            <button type="submit">"Add Role"</button>
        </form>
        <h3>"Assign Role to User"</h3>
        <form>
            <input type="text" placeholder="Username" />
            <input type="text" placeholder="Role" />
            <button type="submit">"Assign"</button>
        </form>
        <h3>"Add Policy to Role"</h3>
        <form>
            <input type="text" placeholder="Role" />
            <input type="text" placeholder="Path" />
            <input type="text" placeholder="Action (read/write/delete)" />
            <input type="text" placeholder="Effect (allow/deny)" />
            <button type="submit">"Add Policy"</button>
        </form>
    }
} 