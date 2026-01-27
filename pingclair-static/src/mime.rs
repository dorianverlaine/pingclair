#![allow(dead_code)]
//! MIME type handling

/// Get MIME type for a file extension
pub fn guess_mime_type(path: &str) -> &'static str {
    mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_types() {
        assert_eq!(guess_mime_type("index.html"), "text/html");
        assert_eq!(guess_mime_type("style.css"), "text/css");
        assert_eq!(guess_mime_type("app.js"), "text/javascript");
    }
}
