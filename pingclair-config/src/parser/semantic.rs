//! Semantic analysis for Pingclairfile
//!
//! Performs macro expansion, validation, and reference resolution.

use crate::parser::ast::*;
use std::collections::HashMap;
use thiserror::Error;

/// Semantic analysis errors
#[derive(Debug, Error)]
pub enum SemanticError {
    #[error("Undefined macro: {name}")]
    UndefinedMacro { name: String },
    
    #[error("Macro argument count mismatch for '{name}': expected {expected}, got {got}")]
    MacroArgCountMismatch { name: String, expected: usize, got: usize },
    
    #[error("Duplicate server name: {name}")]
    DuplicateServer { name: String },
    
    #[error("Duplicate macro name: {name}")]
    DuplicateMacro { name: String },
    
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },
}

type SemanticResult<T> = Result<T, SemanticError>;

/// Semantic analyzer
pub struct SemanticAnalyzer {
    /// Macro definitions
    macros: HashMap<String, MacroDef>,
}

impl SemanticAnalyzer {
    pub fn new() -> Self {
        Self {
            macros: HashMap::new(),
        }
    }

    /// Analyze and transform the AST
    pub fn analyze(&mut self, mut ast: Ast) -> SemanticResult<Ast> {
        // Phase 1: Collect macro definitions
        for macro_node in &ast.macros {
            let macro_def = &macro_node.inner;
            if self.macros.contains_key(&macro_def.name) {
                return Err(SemanticError::DuplicateMacro {
                    name: macro_def.name.clone(),
                });
            }
            self.macros.insert(macro_def.name.clone(), macro_def.clone());
        }

        // Phase 2: Check for duplicate servers
        let mut server_names = HashMap::new();
        for server_node in &ast.servers {
            let name = &server_node.inner.name;
            if server_names.contains_key(name) {
                return Err(SemanticError::DuplicateServer { name: name.clone() });
            }
            server_names.insert(name.clone(), ());
        }

        // Phase 3: Expand macros in servers
        for server_node in &mut ast.servers {
            self.expand_server(&mut server_node.inner)?;
        }

        // Phase 4: Validate configuration
        self.validate(&ast)?;

        Ok(ast)
    }

    fn expand_server(&self, server: &mut ServerBlock) -> SemanticResult<()> {
        // Expand macro calls in directives
        let mut expanded_directives = Vec::new();
        
        for directive in server.directives.drain(..) {
            match directive {
                Directive::MacroCall(call) => {
                    let expanded = self.expand_macro_call(&call)?;
                    expanded_directives.extend(expanded);
                }
                other => {
                    expanded_directives.push(other);
                }
            }
        }
        
        server.directives = expanded_directives;
        
        // Process expanded headers directives
        for directive in &server.directives {
            if let Directive::Headers(headers) = directive {
                // Apply headers configuration to server (could add to server's headers field)
                // For now, just validate
                let _ = headers;
            }
        }

        // Expand macros in route handlers
        if let Some(routes) = &mut server.routes {
            for arm in &mut routes.inner.arms {
                self.expand_handler(&mut arm.inner.handler)?;
            }
        }

        Ok(())
    }

    fn expand_handler(&self, handler: &mut Handler) -> SemanticResult<()> {
        match handler {
            Handler::Proxy(proxy) => {
                // Expand macro calls in proxy config
                let mut expanded_headers = HashMap::new();
                
                for call in proxy.macro_calls.drain(..) {
                    let expanded = self.expand_macro_call(&call)?;
                    for directive in expanded {
                        if let Directive::Headers(ref headers) = directive {
                            // Convert headers to header_up
                            for (k, v) in &headers.set {
                                expanded_headers.insert(k.clone(), Expr::String(v.clone()));
                            }
                        }
                        // Handle header_up from expanded macro
                        if let Directive::Setting { ref key, ref value } = directive {
                            if key == "header_up" {
                                // Would need more sophisticated handling
                            }
                            let _ = value;
                        }
                    }
                }
                
                // Merge expanded headers
                proxy.header_up.extend(expanded_headers);
            }
            Handler::Pipeline(handlers) => {
                for h in handlers {
                    self.expand_handler(h)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn expand_macro_call(&self, call: &MacroCall) -> SemanticResult<Vec<Directive>> {
        let macro_def = self.macros.get(&call.name).ok_or_else(|| {
            SemanticError::UndefinedMacro { name: call.name.clone() }
        })?;

        if macro_def.params.len() != call.args.len() {
            return Err(SemanticError::MacroArgCountMismatch {
                name: call.name.clone(),
                expected: macro_def.params.len(),
                got: call.args.len(),
            });
        }

        // Build substitution map
        let mut substitutions = HashMap::new();
        for (param, arg) in macro_def.params.iter().zip(call.args.iter()) {
            substitutions.insert(param.name.clone(), arg.clone());
        }

        // Clone and substitute in body
        let mut expanded = Vec::new();
        for directive in &macro_def.body {
            let substituted = self.substitute_directive(directive, &substitutions);
            expanded.push(substituted);
        }

        Ok(expanded)
    }

    fn substitute_directive(&self, directive: &Directive, subs: &HashMap<String, Expr>) -> Directive {
        match directive {
            Directive::MacroCall(call) => {
                // Recursively expand nested macro calls
                // For now, just clone
                Directive::MacroCall(MacroCall {
                    name: call.name.clone(),
                    args: call.args.iter().map(|a| self.substitute_expr(a, subs)).collect(),
                })
            }
            Directive::Headers(headers) => {
                Directive::Headers(HeadersConfig {
                    set: headers.set.iter()
                        .map(|(k, v)| (k.clone(), self.substitute_string(v, subs)))
                        .collect(),
                    add: headers.add.iter()
                        .map(|(k, v)| (k.clone(), self.substitute_string(v, subs)))
                        .collect(),
                    remove: headers.remove.clone(),
                })
            }
            Directive::Setting { key, value } => {
                Directive::Setting {
                    key: key.clone(),
                    value: self.substitute_expr(value, subs),
                }
            }
            Directive::Block { name, body } => {
                Directive::Block {
                    name: name.clone(),
                    body: body.iter().map(|d| self.substitute_directive(d, subs)).collect(),
                }
            }
        }
    }

    fn substitute_expr(&self, expr: &Expr, subs: &HashMap<String, Expr>) -> Expr {
        match expr {
            Expr::Ident(name) => {
                if let Some(replacement) = subs.get(name) {
                    replacement.clone()
                } else {
                    expr.clone()
                }
            }
            Expr::Variable(var) => {
                // Check if variable references a macro param
                let parts: Vec<&str> = var.path.split('.').collect();
                if let Some(first) = parts.first() {
                    if let Some(replacement) = subs.get(*first) {
                        return replacement.clone();
                    }
                }
                expr.clone()
            }
            Expr::Array(items) => {
                Expr::Array(items.iter().map(|e| self.substitute_expr(e, subs)).collect())
            }
            Expr::Map(map) => {
                Expr::Map(map.iter()
                    .map(|(k, v)| (k.clone(), self.substitute_expr(v, subs)))
                    .collect())
            }
            _ => expr.clone(),
        }
    }

    fn substitute_string(&self, s: &str, _subs: &HashMap<String, Expr>) -> String {
        // For now, simple string substitution
        // Could be enhanced to handle ${param} in strings
        s.to_string()
    }

    fn validate(&self, ast: &Ast) -> SemanticResult<()> {
        // Validate global config
        if let Some(global) = &ast.global {
            // Check for valid protocol combinations
            let has_h3 = global.inner.protocols.contains(&Protocol::H3);
            let has_h1_or_h2 = global.inner.protocols.contains(&Protocol::H1) 
                || global.inner.protocols.contains(&Protocol::H2);
            
            if has_h3 && !has_h1_or_h2 {
                // H3 alone is valid but might want to warn
            }
        }

        // Validate servers
        for server_node in &ast.servers {
            let server = &server_node.inner;
            
            // Check that server has at least listen or routes
            if server.listen.is_none() && server.routes.is_none() {
                return Err(SemanticError::InvalidConfig {
                    message: format!("Server '{}' needs at least 'listen' or 'route' block", server.name),
                });
            }

            // Validate routes
            if let Some(routes) = &server.routes {
                let mut has_default = false;
                for arm in &routes.inner.arms {
                    if arm.inner.matcher.is_none() {
                        if has_default {
                            return Err(SemanticError::InvalidConfig {
                                message: format!("Server '{}' has multiple default routes", server.name),
                            });
                        }
                        has_default = true;
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for SemanticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn test_duplicate_server_detection() {
        let ast = parse(r#"
            server "example.com" {
                listen: "http://127.0.0.1:80";
            }
            server "example.com" {
                listen: "http://127.0.0.1:8080";
            }
        "#).unwrap();

        let mut analyzer = SemanticAnalyzer::new();
        let result = analyzer.analyze(ast);
        
        assert!(matches!(result, Err(SemanticError::DuplicateServer { .. })));
    }

    #[test]
    fn test_undefined_macro() {
        let ast = parse(r#"
            server "example.com" {
                listen: "http://127.0.0.1:80";
                use undefined_macro!();
            }
        "#).unwrap();

        let mut analyzer = SemanticAnalyzer::new();
        let result = analyzer.analyze(ast);
        
        assert!(matches!(result, Err(SemanticError::UndefinedMacro { .. })));
    }

    #[test]
    fn test_macro_expansion() {
        let ast = parse(r#"
            macro security!() {
                headers {
                    remove: ["Server"];
                    set: {
                        "X-Frame-Options": "DENY",
                    };
                }
            }

            server "example.com" {
                listen: "http://127.0.0.1:80";
                use security!();
            }
        "#).unwrap();

        let mut analyzer = SemanticAnalyzer::new();
        let result = analyzer.analyze(ast);
        
        assert!(result.is_ok());
        let analyzed = result.unwrap();
        assert!(!analyzed.servers[0].inner.directives.is_empty());
    }

    #[test]
    fn test_valid_configuration() {
        let ast = parse(r#"
            global {
                protocols: [H1, H2];
            }

            server "example.com" {
                listen: "http://127.0.0.1:80";
                
                route {
                    match path("/api/*") => {
                        proxy "http://localhost:3000"
                    }
                    _ => {
                        respond 404
                    }
                }
            }
        "#).unwrap();

        let mut analyzer = SemanticAnalyzer::new();
        let result = analyzer.analyze(ast);
        
        assert!(result.is_ok());
    }
}
