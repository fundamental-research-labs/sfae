use sfae_core::service::{ServiceConfig, ServiceRegistry};

pub fn add(id: &str, name: &str, url: &str) -> anyhow::Result<()> {
    let config = ServiceConfig {
        id: id.to_string(),
        display_name: name.to_string(),
        base_url: url.to_string(),
    };
    ServiceRegistry::add(config)?;
    eprintln!("Service '{id}' registered.");
    Ok(())
}

pub fn list() -> anyhow::Result<()> {
    let services = ServiceRegistry::list()?;
    if services.is_empty() {
        eprintln!("No services registered.");
    } else {
        for s in services {
            println!("{:<16} {}", s.id, s.display_name);
        }
    }
    Ok(())
}

pub fn show(id: &str) -> anyhow::Result<()> {
    let config = ServiceRegistry::get(id)?;
    println!("ID:       {}", config.id);
    println!("Name:     {}", config.display_name);
    println!("Base URL: {}", config.base_url);
    Ok(())
}

pub fn remove(id: &str) -> anyhow::Result<()> {
    ServiceRegistry::remove(id)?;
    eprintln!("Service '{id}' removed.");
    Ok(())
}
