//! Generic AST for Caddyfile syntax
//!
//! This AST represents the structure of a Caddyfile:
//! - Directives (Name + Args + Block)
//! - Blocks (List of Directives)

#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    /// Directive name (e.g. "server", "reverse_proxy", "example.com")
    pub name: String,
    
    /// Arguments following the name
    pub args: Vec<String>,
    
    /// Optional block { ... }
    pub block: Option<Block>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub directives: Vec<Directive>,
}

impl Directive {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            args: Vec::new(),
            block: None,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_block(mut self, block: Block) -> Self {
        self.block = Some(block);
        self
    }
}
