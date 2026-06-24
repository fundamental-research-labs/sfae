//! In-memory `SecretStore` implementation used by tests.

use std::collections::HashMap;

use crate::error::SfaeError;

use super::{
    CredentialSetInfo, CredentialSetInput, SecretStore, StoreEntry, StructuredCredentialSetInput,
    StructuredCredentialSetUpdate, parse_structured_credential_set, serialize_credential_set_data,
    serialize_structured_credential_set,
};

/// In-memory secret store for testing.
#[derive(Default)]
pub struct InMemoryStore {
    entries: HashMap<String, String>,
    credential_sets: Vec<CredentialSetInfo>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemoryStore {
    fn set(&mut self, entry: StoreEntry<'_>) -> Result<(), SfaeError> {
        self.entries
            .insert(entry.key.to_string(), entry.value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<String, SfaeError> {
        self.entries
            .get(key)
            .cloned()
            .ok_or_else(|| SfaeError::CredentialNotFound(key.to_string()))
    }

    fn delete(&mut self, key: &str) -> Result<(), SfaeError> {
        self.entries
            .remove(key)
            .ok_or_else(|| SfaeError::CredentialNotFound(key.to_string()))?;
        Ok(())
    }

    fn forget(&mut self, key: &str) -> Result<(), SfaeError> {
        self.delete(key)
    }

    fn list_keys(&self) -> Result<Vec<String>, SfaeError> {
        let mut keys: Vec<String> = self.entries.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }

    fn supports_credential_sets(&self) -> bool {
        true
    }

    fn store_credential_set(&mut self, input: CredentialSetInput<'_>) -> Result<String, SfaeError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut keys: Vec<String> = input.values.keys().cloned().collect();
        keys.sort();

        let json = serde_json::to_string(input.values)?;
        self.entries.insert(id.clone(), json);

        self.credential_sets.push(CredentialSetInfo {
            id: id.clone(),
            domain: input.domain.to_string(),
            label: input.label.map(String::from),
            keys,
            metadata: HashMap::new(),
        });

        Ok(id)
    }

    fn store_structured_credential_set(
        &mut self,
        input: StructuredCredentialSetInput<'_>,
    ) -> Result<String, SfaeError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut keys: Vec<String> = input.values.keys().cloned().collect();
        keys.sort();

        let json = serialize_structured_credential_set(&input)?;
        self.entries.insert(id.clone(), json);

        self.credential_sets.push(CredentialSetInfo {
            id: id.clone(),
            domain: input.domain.to_string(),
            label: input.label.map(String::from),
            keys,
            metadata: input.metadata.cloned().unwrap_or_default(),
        });

        Ok(id)
    }

    fn update_structured_credential_set(
        &mut self,
        input: StructuredCredentialSetUpdate<'_>,
    ) -> Result<(), SfaeError> {
        let blob = self.get(input.id)?;
        let mut data = parse_structured_credential_set(&blob)?;
        super::merge_structured_credential_data(&mut data, &input);
        let json = serialize_credential_set_data(&data)?;
        let Some(set_index) = self.credential_sets.iter().position(|s| s.id == input.id) else {
            return Err(SfaeError::CredentialNotFound(input.id.to_string()));
        };
        self.entries.insert(input.id.to_string(), json);

        self.credential_sets[set_index].keys = data.values.keys().cloned().collect();
        self.credential_sets[set_index].keys.sort();
        self.credential_sets[set_index].metadata = data.metadata;
        Ok(())
    }

    fn list_credential_sets(
        &self,
        domain: Option<&str>,
    ) -> Result<Vec<CredentialSetInfo>, SfaeError> {
        Ok(match domain {
            Some(d) => self
                .credential_sets
                .iter()
                .filter(|s| s.domain == d)
                .cloned()
                .collect(),
            None => self.credential_sets.clone(),
        })
    }

    fn delete_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
        self.forget_credential_set(id)?;
        self.entries.remove(id);
        Ok(())
    }

    fn forget_credential_set(&mut self, id: &str) -> Result<(), SfaeError> {
        let found = self.credential_sets.iter().any(|s| s.id == id);
        self.credential_sets.retain(|s| s.id != id);
        found
            .then_some(())
            .ok_or_else(|| SfaeError::CredentialNotFound(id.to_string()))
    }
}
