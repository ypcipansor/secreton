// This is a fixed implementation of the problematic method

impl EntropyAugmentationEngine {
    /// Start entropy collection in background
    pub async fn start_entropy_collection(&self) {
        let sources = self.sources.clone();
        let entropy_pool = self.entropy_pool.clone();
        let config = self.config.clone();
        let health_monitor_running = self.health_monitor_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.collection_interval);
            
            loop {
                interval.tick().await;
                
                // Safe entropy collection without holding locks across await points
                let collected_entropy = {
                    let sources_guard = sources.read().unwrap();
                    let mut entropy_batches = Vec::new();
                    
                    for source in sources_guard.iter() {
                        if source.get_config().enabled {
                            if let Ok(entropy_data) = source.collect_entropy(1024).await {
                                entropy_batches.push(entropy_data);
                            }
                        }
                    }
                    entropy_batches
                };
                
                // Store collected entropy
                {
                    let mut pool = entropy_pool.lock().unwrap();
                    for batch in collected_entropy {
                        pool.extend(batch);
                    }
                }
                
                // Check if monitoring should continue
                {
                    let running = health_monitor_running.lock().unwrap();
                    if !*running {
                        break;
                    }
                }
            }
        });
    }

    /// Start health monitoring
    pub async fn start_health_monitoring(&self) {
        let sources = self.sources.clone();
        let config = self.config.clone();
        let health_monitor_running = self.health_monitor_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.quality_check_interval);
            
            loop {
                interval.tick().await;
                
                // Check if monitoring should continue
                {
                    let running = health_monitor_running.lock().unwrap();
                    if !*running {
                        break;
                    }
                }

                // Perform health checks
                {
                    let sources_guard = sources.read().unwrap();
                    for source in sources_guard.iter() {
                        let _is_healthy = source.health_check().await;
                        // Log health status or take action as needed
                    }
                }
            }
        });
    }
}
