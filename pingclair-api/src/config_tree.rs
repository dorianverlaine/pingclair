// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Caddy-style config tree traversal for the Admin API

use serde_json::Value;

/// Why a traversal operation could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// The target path does not exist.
    NotFound,
    /// The target already exists where the operation requires a fresh node.
    Conflict,
    /// The path or value is malformed for the operation.
    Invalid(String),
}

impl TreeError {
    /// 📣 Renders the error as a client-facing message.
    pub fn message(&self) -> String {
        match self {
            TreeError::NotFound => "config path does not exist".to_string(),
            TreeError::Conflict => "config path already exists".to_string(),
            TreeError::Invalid(reason) => format!("invalid config path: {reason}"),
        }
    }
}

/// How a write operation treats an existing target, matching Caddy's API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// POST: create or replace; arrays append at the end or replace in range.
    Upsert,
    /// PUT: strictly create; arrays insert at an index and shift the rest.
    Create,
    /// PATCH: strictly replace an existing target.
    Replace,
}

/// 🧭 Splits a `/config/...` request path into segments, ignoring empties.
pub fn segments_from_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

/// 📖 Resolves a node by path without modifying the document.
pub fn get<'a>(doc: &'a Value, segments: &[String]) -> Result<&'a Value, TreeError> {
    let mut current = doc;
    for segment in segments {
        current = match current {
            Value::Object(map) => map.get(segment).ok_or(TreeError::NotFound)?,
            Value::Array(items) => {
                let index = parse_index(segment)?;
                items.get(index).ok_or(TreeError::NotFound)?
            }
            _ => return Err(TreeError::Invalid("cannot descend into a scalar".into())),
        };
    }
    Ok(current)
}

/// ✍️ Writes `value` at `segments` with Caddy's POST/PUT/PATCH semantics.
pub fn set(
    doc: &mut Value,
    segments: &[String],
    value: Value,
    mode: Mode,
) -> Result<(), TreeError> {
    if segments.is_empty() {
        return match mode {
            Mode::Upsert | Mode::Replace => {
                *doc = value;
                Ok(())
            }
            Mode::Create if doc.is_null() => {
                *doc = value;
                Ok(())
            }
            Mode::Create => Err(TreeError::Conflict),
        };
    }

    let (parent, last) = traverse_parent_mut(doc, segments)?;
    match parent {
        Value::Object(map) => match mode {
            Mode::Upsert => {
                map.insert(last, value);
                Ok(())
            }
            Mode::Create if map.contains_key(&last) => Err(TreeError::Conflict),
            Mode::Create => {
                map.insert(last, value);
                Ok(())
            }
            Mode::Replace if !map.contains_key(&last) => Err(TreeError::NotFound),
            Mode::Replace => {
                map.insert(last, value);
                Ok(())
            }
        },
        Value::Array(items) => {
            let index = parse_index(&last)?;
            match mode {
                Mode::Upsert if index == items.len() => {
                    items.push(value);
                    Ok(())
                }
                Mode::Upsert if index < items.len() => {
                    items[index] = value;
                    Ok(())
                }
                Mode::Upsert => Err(TreeError::Invalid("array index out of range".into())),
                Mode::Create if index == items.len() => {
                    items.push(value);
                    Ok(())
                }
                Mode::Create if index < items.len() => {
                    items.insert(index, value);
                    Ok(())
                }
                Mode::Create => Err(TreeError::Invalid("array index out of range".into())),
                Mode::Replace if index < items.len() => {
                    items[index] = value;
                    Ok(())
                }
                Mode::Replace => Err(TreeError::NotFound),
            }
        }
        _ => Err(TreeError::Invalid("cannot write into a scalar".into())),
    }
}

/// 🗑️ Removes the node at `segments` and returns the removed value.
pub fn remove(doc: &mut Value, segments: &[String]) -> Result<Value, TreeError> {
    if segments.is_empty() {
        return Ok(std::mem::replace(doc, Value::Null));
    }
    let (parent, last) = traverse_parent_mut(doc, segments)?;
    match parent {
        Value::Object(map) => map.remove(&last).ok_or(TreeError::NotFound),
        Value::Array(items) => {
            let index = parse_index(&last)?;
            if index < items.len() {
                Ok(items.remove(index))
            } else {
                Err(TreeError::NotFound)
            }
        }
        _ => Err(TreeError::Invalid("cannot delete from a scalar".into())),
    }
}

/// 🌱 Applies a POST `...` expansion: an array body appends every element.
pub fn expand_append(doc: &mut Value, segments: &[String], body: &Value) -> Result<(), TreeError> {
    let Value::Array(elements) = body else {
        return Err(TreeError::Invalid(
            "`...` expansion requires an array body".into(),
        ));
    };
    let Value::Array(target) = get(doc, segments)? else {
        return Err(TreeError::Invalid(
            "`...` expansion requires an array target".into(),
        ));
    };
    for (index, element) in (target.len()..).zip(elements.iter()) {
        let mut path = segments.to_vec();
        path.push(index.to_string());
        set(doc, &path, element.clone(), Mode::Upsert)?;
    }
    Ok(())
}

/// 🏷️ Finds the document path of the first object tagged with `@id == name`.
///
/// Caddy lets any JSON object carry an `@id` and then addresses it as
/// `/id/<name>`; the returned path points at that object so the caller can
/// read or mutate it like any other traversal target.
pub fn find_id_path(doc: &Value, name: &str) -> Option<Vec<String>> {
    fn walk(node: &Value, path: &mut Vec<String>, name: &str) -> Option<Vec<String>> {
        match node {
            Value::Object(map) => {
                if map.get("@id").and_then(Value::as_str) == Some(name) {
                    return Some(path.clone());
                }
                for (key, child) in map {
                    path.push(key.clone());
                    if let Some(found) = walk(child, path, name) {
                        return Some(found);
                    }
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    path.push(index.to_string());
                    if let Some(found) = walk(child, path, name) {
                        return Some(found);
                    }
                    path.pop();
                }
            }
            _ => {}
        }
        None
    }
    walk(doc, &mut Vec::new(), name)
}

fn traverse_parent_mut<'a>(
    doc: &'a mut Value,
    segments: &[String],
) -> Result<(&'a mut Value, String), TreeError> {
    let mut current = doc;
    for segment in &segments[..segments.len() - 1] {
        current = match current {
            Value::Object(map) => map.get_mut(segment).ok_or(TreeError::NotFound)?,
            Value::Array(items) => {
                let index = parse_index(segment)?;
                items.get_mut(index).ok_or(TreeError::NotFound)?
            }
            _ => return Err(TreeError::Invalid("cannot descend into a scalar".into())),
        };
    }
    Ok((current, segments[segments.len() - 1].clone()))
}

fn parse_index(segment: &str) -> Result<usize, TreeError> {
    segment
        .parse::<usize>()
        .map_err(|_| TreeError::Invalid(format!("array index expected, got `{segment}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "servers": [{
                "name": "_",
                "listen": ["127.0.0.1:8080"],
                "routes": [{
                    "path": "/*",
                    "handler": {"type": "respond", "status": 200, "body": "hi"}
                }]
            }]
        })
    }

    #[test]
    fn get_resolves_object_keys_and_array_indices() {
        let doc = sample();
        let segments = segments_from_path("/servers/0/routes/0/handler/body");
        assert_eq!(get(&doc, &segments).unwrap(), &json!("hi"));
        assert!(get(&doc, &segments_from_path("/servers/9")).is_err());
    }

    #[test]
    fn post_upserts_missing_and_existing_object_keys() {
        let mut doc = sample();
        set(
            &mut doc,
            &segments_from_path("/servers/0/routes/0/handler/body"),
            json!("updated"),
            Mode::Upsert,
        )
        .unwrap();
        assert_eq!(doc["servers"][0]["routes"][0]["handler"]["body"], "updated");

        set(
            &mut doc,
            &segments_from_path("/servers/0/extra"),
            json!(true),
            Mode::Upsert,
        )
        .unwrap();
        assert_eq!(doc["servers"][0]["extra"], true);
    }

    #[test]
    fn put_inserts_into_arrays_and_rejects_existing_keys() {
        let mut doc = sample();
        assert!(matches!(
            set(
                &mut doc,
                &segments_from_path("/servers/0/name"),
                json!("x"),
                Mode::Create,
            ),
            Err(TreeError::Conflict)
        ));
        set(
            &mut doc,
            &segments_from_path("/servers/0/listen/0"),
            json!("127.0.0.1:9999"),
            Mode::Create,
        )
        .unwrap();
        assert_eq!(
            doc["servers"][0]["listen"],
            json!(["127.0.0.1:9999", "127.0.0.1:8080"])
        );
    }

    #[test]
    fn patch_replaces_existing_nodes_only() {
        let mut doc = sample();
        assert!(matches!(
            set(
                &mut doc,
                &segments_from_path("/servers/0/missing"),
                json!(1),
                Mode::Replace,
            ),
            Err(TreeError::NotFound)
        ));
        set(
            &mut doc,
            &segments_from_path("/servers/0/routes/0/handler/body"),
            json!("patched"),
            Mode::Replace,
        )
        .unwrap();
        assert_eq!(doc["servers"][0]["routes"][0]["handler"]["body"], "patched");
    }

    #[test]
    fn delete_removes_nodes_and_missing_paths_fail() {
        let mut doc = sample();
        assert!(matches!(
            remove(&mut doc, &segments_from_path("/servers/0/nope")),
            Err(TreeError::NotFound)
        ));
        let removed = remove(
            &mut doc,
            &segments_from_path("/servers/0/routes/0/handler/body"),
        )
        .unwrap();
        assert_eq!(removed, json!("hi"));
        assert!(doc["servers"][0]["routes"][0]["handler"]["body"].is_null());
    }

    #[test]
    fn expand_appends_every_array_element() {
        let mut doc = sample();
        expand_append(
            &mut doc,
            &segments_from_path("/servers/0/listen"),
            &json!(["127.0.0.1:1", "127.0.0.1:2"]),
        )
        .unwrap();
        assert_eq!(
            doc["servers"][0]["listen"],
            json!(["127.0.0.1:8080", "127.0.0.1:1", "127.0.0.1:2"])
        );
    }

    #[test]
    fn id_tags_resolve_to_their_object_path() {
        let mut doc = sample();
        doc["servers"][0]["routes"][0]["handler"]["@id"] = json!("msg");

        let path = find_id_path(&doc, "msg").expect("tag is found");
        assert_eq!(path, ["servers", "0", "routes", "0", "handler"]);
        assert!(find_id_path(&doc, "missing").is_none());
    }
}
