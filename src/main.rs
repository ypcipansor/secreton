use vault_adhyaksa::storage::Storage;
use vault_adhyaksa::services::lease::revoke_lease;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Hello, world!");
    let state = vault_adhyaksa::core::init_state().await?;
    let storage = state.storage.clone();
    tokio::spawn(async move {
        let storage = storage.as_any().downcast_ref::<Storage>().unwrap().clone();
        loop {
            match storage.get_expired_leases().await {
                Ok(leases) => {
                    for lease in leases {
                        let _ = revoke_lease(&storage, &lease.id).await;
                    }
                },
                Err(e) => eprintln!("[LEASE CLEANUP ERROR] {}", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(300)).await; // 5 menit
        }
    });
}
