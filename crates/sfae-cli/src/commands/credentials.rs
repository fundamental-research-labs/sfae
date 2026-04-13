use crate::store_factory::create_store;

pub fn run(domain: Option<&str>, username: Option<&str>) -> anyhow::Result<()> {
    let store = create_store();

    if store.supports_credential_sets() {
        let sets = store.list_credential_sets(domain)?;
        let filtered: Vec<_> = if let Some(user) = username {
            sets.into_iter()
                .filter(|s| s.label.as_deref() == Some(user))
                .collect()
        } else {
            sets
        };

        if filtered.is_empty() {
            let target = match (domain, username) {
                (Some(d), Some(u)) => format!("{u}@{d}"),
                (Some(d), None) => d.to_string(),
                (None, Some(u)) => format!("user '{u}'"),
                (None, None) => "any domain".to_string(),
            };
            eprintln!("No credentials stored for {target}.");
        } else {
            for s in &filtered {
                let label = s.label.as_deref().unwrap_or("-");
                println!(
                    "{id}  {domain}  {label}  [{keys}]",
                    id = s.id,
                    domain = s.domain,
                    keys = s.keys.join(", "),
                );
            }
        }
        return Ok(());
    }

    // Legacy fallback: flat domain_TYPE keys
    let Some(domain) = domain else {
        anyhow::bail!("domain is required for legacy credential stores");
    };
    let types = sfae_core::store::list_credential_types(&*store, domain, username)?;
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
