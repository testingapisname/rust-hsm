# CLI Architecture

This document describes the modular command architecture introduced in December 2025 to improve maintainability and organization.

## Overview

The CLI has been refactored from a monolithic 842-line `main.rs` to a clean, modular architecture with only 35 lines in the main entry point.

## Architecture

### Entry Point
- **[main.rs](../crates/rust-hsm-cli/src/main.rs)** (35 lines)
  - Configuration loading
  - Tracing initialization
  - Command dispatch to handlers

### Command Organization

Commands are organized by functional category in the `commands/` directory:

#### Core Modules
- **[mod.rs](../crates/rust-hsm-cli/src/commands/mod.rs)** - Main command dispatcher with routing logic
- **[common.rs](../crates/rust-hsm-cli/src/commands/common.rs)** - Shared utilities and CommandContext

#### Command Categories

| Module | Purpose | Commands |
|--------|---------|----------|
| **[info.rs](../crates/rust-hsm-cli/src/commands/info.rs)** | Information & listing | `info`, `list-slots`, `list-mechanisms`, `list-objects` |
| **[token.rs](../crates/rust-hsm-cli/src/commands/token.rs)** | Token management | `init-token`, `init-pin`, `delete-token` |
| **[keys.rs](../crates/rust-hsm-cli/src/commands/keys.rs)** | Key management | `gen-keypair`, `delete-key`, `inspect-key`, `export-pubkey` |
| **[crypto.rs](../crates/rust-hsm-cli/src/commands/crypto.rs)** | Asymmetric crypto | `sign`, `verify`, `encrypt`, `decrypt` |
| **[symmetric.rs](../crates/rust-hsm-cli/src/commands/symmetric.rs)** | Symmetric crypto | `gen-symmetric-key`, `encrypt-symmetric`, `decrypt-symmetric` |
| **[key_wrap.rs](../crates/rust-hsm-cli/src/commands/key_wrap.rs)** | Key wrapping | `wrap-key`, `unwrap-key` |
| **[mac.rs](../crates/rust-hsm-cli/src/commands/mac.rs)** | Message authentication | `gen-hmac-key`, `hmac-sign`, `hmac-verify`, `gen-cmac-key`, `cmac-sign`, `cmac-verify` |
| **[util.rs](../crates/rust-hsm-cli/src/commands/util.rs)** | Utilities | `benchmark`, `audit-keys`, `explain-error`, `find-key`, `diff-keys`, `gen-random`, `hash`, `gen-csr` |
| **[analyze.rs](../crates/rust-hsm-cli/src/commands/analyze.rs)** | Observability | `analyze` |

## Benefits

### 📈 Maintainability
- **Focused modules**: Each handler focuses on a specific command category
- **Separation of concerns**: Clear boundaries between different functionality
- **Reduced complexity**: No more 842-line files

### 🧪 Testability
- **Isolated testing**: Each command handler can be tested independently
- **Mocking**: Easier to mock dependencies for unit tests
- **Integration**: Clear interfaces for integration testing

### 🔄 Code Reuse
- **Shared utilities**: Common PIN handling, configuration, and context management
- **DRY principle**: Eliminates duplicate PIN and config handling code
- **Consistent patterns**: Standardized error handling and logging

### 🚀 Extensibility
- **Easy additions**: New commands just add handlers to appropriate modules
- **Plugin architecture**: Commands are cleanly separated and self-contained
- **Future-proof**: Structure supports future command categories

## Shared Infrastructure

### CommandContext
The `CommandContext` struct provides shared state and utilities:

```rust
pub struct CommandContext {
    pub module_path: String,
    pub config: Config,
}
```

### PIN Handling
Centralized PIN handling supports multiple input methods:
- Command-line arguments
- Stdin input (`--pin-stdin` flag)
- Environment variables (through config)

### Error Handling
Consistent error handling across all command handlers using `anyhow::Result`.

## Adding New Commands

1. **Add to CLI definition**: Update `Commands` enum in `cli.rs`
2. **Choose handler module**: Add to existing category or create new module
3. **Implement handler**: Use shared utilities from `common.rs`
4. **Update dispatcher**: Add routing in `commands/mod.rs`
5. **Add tests**: Update integration test scripts
6. **Document**: Update command documentation

## Migration Benefits

- ✅ **All 55 tests pass** - No functionality lost
- ✅ **35-line main.rs** - 96% reduction in main file size  
- ✅ **Modular structure** - Commands organized by purpose
- ✅ **Shared utilities** - DRY principle applied
- ✅ **Future-ready** - Easy to extend and maintain

The refactoring maintains full backward compatibility while dramatically improving code organization and maintainability.