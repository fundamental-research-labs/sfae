//! Redis protocol execution with SFAE credential placeholder resolution.
//!
//! Redis requests use the same `{KEY}` substitution model as HTTP and
//! Postgres, while keeping Redis transport concerns isolated here.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use redis::Value as RedisValue;
use serde::Serialize;
use serde_json::{Map, Number, Value, json};

use crate::error::SfaeError;
use crate::proxy::{CredentialLookup, PlaceholderMap};

/// A Redis request with placeholders in the connection URL or command args.
#[derive(Debug, Clone)]
pub struct RedisRequest {
    pub url: String,
    pub command: String,
    pub args: Vec<String>,
}

/// Result returned by a Redis command execution.
#[derive(Debug, Serialize)]
pub struct RedisResponse {
    pub value: Value,
}

/// Context for resolving or executing a Redis request.
pub struct RedisRequestCtx<'a, 'store> {
    pub lookup: &'a CredentialLookup<'store>,
    pub request: &'a RedisRequest,
}

#[derive(Clone, Copy)]
enum PlaceholderAction {
    Resolve,
    Mask,
}

struct MapRequestCtx<'a, 'store> {
    lookup: &'a CredentialLookup<'store>,
    request: &'a RedisRequest,
    action: PlaceholderAction,
}

/// Execute a Redis command after resolving credentials.
pub fn execute(ctx: RedisRequestCtx<'_, '_>) -> Result<RedisResponse, SfaeError> {
    let request = map_request(MapRequestCtx {
        lookup: ctx.lookup,
        request: ctx.request,
        action: PlaceholderAction::Resolve,
    })?;
    let client = redis::Client::open(request.url.as_str())
        .map_err(|e| SfaeError::Other(format!("Redis client setup failed: {e}")))?;
    let mut connection = client
        .get_connection()
        .map_err(|e| SfaeError::Other(format!("Redis connection failed: {e}")))?;
    let mut command = redis::cmd(&request.command);
    for arg in &request.args {
        command.arg(arg);
    }
    let value = command
        .query::<RedisValue>(&mut connection)
        .map_err(|e| SfaeError::Other(format!("Redis command failed: {e}")))?;
    Ok(RedisResponse {
        value: redis_value_to_json(value),
    })
}

/// Return a masked preview of a Redis request without opening a connection.
pub fn mask(ctx: RedisRequestCtx<'_, '_>) -> Result<RedisRequest, SfaeError> {
    map_request(MapRequestCtx {
        lookup: ctx.lookup,
        request: ctx.request,
        action: PlaceholderAction::Mask,
    })
}

fn map_request(ctx: MapRequestCtx<'_, '_>) -> Result<RedisRequest, SfaeError> {
    let map = ctx.lookup.fetch()?;
    let placeholders = PlaceholderMap(&map);
    let apply = |value: &str| match ctx.action {
        PlaceholderAction::Resolve => placeholders.resolve(value),
        PlaceholderAction::Mask => placeholders.mask(value),
    };

    Ok(RedisRequest {
        url: apply(&ctx.request.url)?,
        command: apply(&ctx.request.command)?,
        args: ctx
            .request
            .args
            .iter()
            .map(|arg| apply(arg))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn redis_value_to_json(value: RedisValue) -> Value {
    match value {
        RedisValue::Nil => Value::Null,
        RedisValue::Int(value) => Value::Number(value.into()),
        RedisValue::BulkString(bytes) => bytes_to_json(bytes),
        RedisValue::Array(values) => {
            Value::Array(values.into_iter().map(redis_value_to_json).collect())
        }
        RedisValue::SimpleString(value) => Value::String(value),
        RedisValue::Okay => Value::String("OK".to_string()),
        RedisValue::Map(entries) => redis_map_to_json(entries),
        RedisValue::Attribute { data, attributes } => json!({
            "data": redis_value_to_json(*data),
            "attributes": redis_map_to_json(attributes)
        }),
        RedisValue::Set(values) => {
            Value::Array(values.into_iter().map(redis_value_to_json).collect())
        }
        RedisValue::Double(value) => Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(value.to_string())),
        RedisValue::Boolean(value) => Value::Bool(value),
        RedisValue::VerbatimString { text, .. } => Value::String(text),
        RedisValue::BigNumber(bytes) => bytes_to_json(bytes),
        RedisValue::Push { kind, data } => json!({
            "kind": format!("{kind:?}"),
            "data": Value::Array(data.into_iter().map(redis_value_to_json).collect())
        }),
        RedisValue::ServerError(error) => json!({
            "error": {
                "code": error.code(),
                "details": error.details()
            }
        }),
        other => Value::String(format!("{other:?}")),
    }
}

fn redis_map_to_json(entries: Vec<(RedisValue, RedisValue)>) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(redis_key_to_json_key(key), redis_value_to_json(value));
    }
    Value::Object(object)
}

fn redis_key_to_json_key(value: RedisValue) -> String {
    match redis_value_to_json(value) {
        Value::String(value) => value,
        value => value.to_string(),
    }
}

fn bytes_to_json(bytes: Vec<u8>) -> Value {
    String::from_utf8(bytes)
        .map(Value::String)
        .unwrap_or_else(|error| json!({ "base64": BASE64.encode(error.into_bytes()) }))
}
