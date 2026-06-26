//! Postgres protocol execution with SFAE credential placeholder resolution.
//!
//! This module keeps SQL transport separate from the HTTP proxy while sharing
//! the same credential lookup and `{KEY}` substitution behavior.

use postgres::{Client, NoTls, SimpleQueryMessage, SimpleQueryRow};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::SfaeError;
use crate::proxy::{CredentialLookup, PlaceholderMap};

/// A Postgres request with placeholders in the connection URL or SQL text.
#[derive(Debug, Clone)]
pub struct PostgresRequest {
    pub url: String,
    pub query: String,
}

/// Result returned by a Postgres simple-query execution.
#[derive(Debug, Serialize)]
pub struct PostgresResponse {
    pub rows: Vec<Value>,
    pub rows_affected: u64,
}

/// Context for resolving or executing a Postgres request.
pub struct PostgresRequestCtx<'a, 'store> {
    pub lookup: &'a CredentialLookup<'store>,
    pub request: &'a PostgresRequest,
}

#[derive(Clone, Copy)]
enum PlaceholderAction {
    Resolve,
    Mask,
}

struct MapRequestCtx<'a, 'store> {
    lookup: &'a CredentialLookup<'store>,
    request: &'a PostgresRequest,
    action: PlaceholderAction,
}

/// Execute SQL over the Postgres wire protocol after resolving credentials.
pub fn execute(ctx: PostgresRequestCtx<'_, '_>) -> Result<PostgresResponse, SfaeError> {
    let request = map_request(MapRequestCtx {
        lookup: ctx.lookup,
        request: ctx.request,
        action: PlaceholderAction::Resolve,
    })?;
    let mut client = Client::connect(&request.url, NoTls)
        .map_err(|e| SfaeError::Other(format!("Postgres connection failed: {e}")))?;
    let messages = client
        .simple_query(&request.query)
        .map_err(|e| SfaeError::Other(format!("Postgres query failed: {e}")))?;
    Ok(messages_to_response(messages))
}

/// Return a masked preview of a Postgres request without opening a connection.
pub fn mask(ctx: PostgresRequestCtx<'_, '_>) -> Result<PostgresRequest, SfaeError> {
    map_request(MapRequestCtx {
        lookup: ctx.lookup,
        request: ctx.request,
        action: PlaceholderAction::Mask,
    })
}

fn map_request(ctx: MapRequestCtx<'_, '_>) -> Result<PostgresRequest, SfaeError> {
    let map = ctx.lookup.fetch()?;
    let placeholders = PlaceholderMap(&map);
    Ok(PostgresRequest {
        url: match ctx.action {
            PlaceholderAction::Resolve => placeholders.resolve(&ctx.request.url)?,
            PlaceholderAction::Mask => placeholders.mask(&ctx.request.url)?,
        },
        query: match ctx.action {
            PlaceholderAction::Resolve => placeholders.resolve(&ctx.request.query)?,
            PlaceholderAction::Mask => placeholders.mask(&ctx.request.query)?,
        },
    })
}

fn messages_to_response(messages: Vec<SimpleQueryMessage>) -> PostgresResponse {
    let mut rows = Vec::new();
    let mut rows_affected = 0;

    for message in messages {
        match message {
            SimpleQueryMessage::Row(row) => rows.push(row_to_value(&row)),
            SimpleQueryMessage::CommandComplete(count) => rows_affected += count,
            _ => {}
        }
    }

    PostgresResponse {
        rows,
        rows_affected,
    }
}

fn row_to_value(row: &SimpleQueryRow) -> Value {
    let mut object = Map::new();
    for (idx, column) in row.columns().iter().enumerate() {
        let value = row
            .get(idx)
            .map(|cell| Value::String(cell.to_string()))
            .unwrap_or(Value::Null);
        object.insert(column.name().to_string(), value);
    }
    Value::Object(object)
}
