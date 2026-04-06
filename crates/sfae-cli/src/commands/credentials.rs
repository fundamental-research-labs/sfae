use sfae_core::store::list_credential_types;

use crate::store_factory::create_store;

pub fn run(domain: &str, username: Option<&str>) -> anyhow::Result<()> {
    let store = create_store();
    let types = list_credential_types(&*store, domain, username)?;
    if types.is_empty() {
        let target = match username {
            Some(user) => format!("{user}@{domain}"),
            None => domain.to_string(),
        };
        eprintln!("No credentials stored for '{target}'.");
    } else {
        for ct in types {
            println!("{ct}");
        }
    }
    Ok(())
}
