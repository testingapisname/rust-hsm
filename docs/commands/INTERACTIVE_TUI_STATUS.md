# Interactive TUI Implementation Status

## Overview

The Interactive TUI mode provides a terminal-based user interface for the rust-hsm-cli, built with [ratatui](https://ratatui.rs/) and [crossterm](https://docs.rs/crossterm/). This document tracks the implementation progress and identifies remaining work.

## What We've Accomplished ✅

### Core TUI Framework
- **Complete terminal management**: Built with ratatui 0.28 + crossterm 0.28
- **Menu-driven interface**: 6 main categories with hierarchical navigation
- **Scrollable output**: Full PageUp/PageDown support for large command outputs
- **Clean display**: Tracing disabled for interactive mode to prevent corruption
- **Error handling**: Graceful error display and recovery
- **Status feedback**: Real-time operation status with emojis and progress indicators

### Menu Structure
```
🔐 rust-hsm Interactive Interface
├── 📊 Information & Status
├── 🎫 Token Management  
├── 🔑 Key Operations
├── 🔐 Cryptographic Operations
├── 🔄 Symmetric Operations
└── 🔧 Troubleshooting
```

### Navigation Features
- **Arrow keys**: Up/down navigation through menus
- **Enter**: Select menu items and execute commands
- **Backspace/Escape**: Return to previous menu level
- **PageUp/PageDown**: Scroll through command output (working!)
- **Q**: Quit application

### Implemented Commands (Information & Status)
| Command | Status | Implementation |
|---------|--------|----------------|
| **info** | ✅ Complete | Real PKCS#11 library information with version details |
| **list-slots** | ✅ Complete | Real slot enumeration with token presence detection |
| **list-mechanisms** | ⚠️ Placeholder | Shows static text, needs real command execution |
| **list-objects** | ⚠️ Placeholder | Shows static text, needs real command execution |

### Technical Achievements
- **Real PKCS#11 integration**: Direct cryptoki library calls, not shell commands
- **Consistent scrolling**: Fixed logic mismatch between render and scroll methods  
- **Error resilience**: Commands that fail don't crash the TUI
- **Memory management**: Proper PKCS#11 initialize/finalize lifecycle
- **Docker testing**: Tested with multiple HSM providers (SoftHSM2, Kryoptic)

## Current Implementation Details

### File Structure
```
crates/rust-hsm-cli/src/commands/interactive.rs  (765 lines)
├── InteractiveApp struct
├── MenuCategory enum (6 categories)  
├── Navigation logic (handle_input)
├── Real command execution (execute_info_command, execute_list_slots_command)
├── Scrolling system (scroll_up, scroll_down)
├── UI rendering (render_main_menu, render_submenu, render_details)
└── Error handling and status management
```

### Working Command Execution Example
```rust
// Real PKCS#11 info command
fn execute_info_command(&self) -> Result<Vec<String>> {
    let pkcs11 = Pkcs11::new(&self.module_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    
    let info = pkcs11.get_library_info()?;
    let mut output = vec![];
    output.push("=== PKCS#11 Library Information ===".to_string());
    output.push(format!("Library: {}", info.library_description()));
    // ... more real data
    
    pkcs11.finalize();
    Ok(output)
}
```

## What Needs to be Completed 🔄

### 1. Information & Status Category (Priority: HIGH)
- **list-mechanisms**: Replace placeholder with real mechanism enumeration
  - Show supported cryptographic mechanisms (RSA, ECDSA, AES-GCM, etc.)
  - Display capabilities (encrypt, decrypt, sign, verify, etc.)
  - Show key size ranges where applicable
- **list-objects**: Replace placeholder with real object listing
  - Enumerate public objects (no PIN required)
  - Show object types (public key, private key, certificate, etc.)
  - Display object labels and basic attributes
  - Handle multiple tokens gracefully

### 2. Token Management Category (Priority: HIGH)
| Command | Current Status | Implementation Needed |
|---------|---------------|----------------------|
| **init-token** | Placeholder | Real token initialization with PIN prompts |
| **init-pin** | Placeholder | User PIN setup with security validation |
| **delete-token** | Placeholder | Token deletion with confirmation prompts |

### 3. Key Operations Category (Priority: MEDIUM)  
| Command | Current Status | Implementation Needed |
|---------|---------------|----------------------|
| **gen-keypair** | Placeholder | Interactive key generation with parameter selection |
| **delete-key** | Placeholder | Key deletion with confirmation and search |
| **export-pubkey** | Placeholder | Public key export with format options |
| **inspect-key** | Placeholder | Detailed key attribute display |

### 4. Cryptographic Operations Category (Priority: MEDIUM)
| Command | Current Status | Implementation Needed |
|---------|---------------|----------------------|
| **sign** | Placeholder | File selection and signing workflow |
| **verify** | Placeholder | Signature verification with file inputs |
| **encrypt** | Placeholder | Encryption with key selection |
| **decrypt** | Placeholder | Decryption workflow |

### 5. Symmetric Operations Category (Priority: LOW)
| Command | Current Status | Implementation Needed |
|---------|---------------|----------------------|
| **gen-symmetric-key** | Placeholder | AES key generation with size options |
| **encrypt-symmetric** | Placeholder | AES-GCM encryption workflow |
| **decrypt-symmetric** | Placeholder | AES-GCM decryption workflow |
| **wrap-key** | Placeholder | Key wrapping operations |

### 6. Troubleshooting Category (Priority: LOW)
| Command | Current Status | Implementation Needed |
|---------|---------------|----------------------|
| **explain-error** | Placeholder | Error code lookup and context help |
| **find-key** | Placeholder | Fuzzy key search functionality |
| **diff-keys** | Placeholder | Key comparison display |
| **audit-keys** | Placeholder | Security audit results |

## Technical Challenges to Address

### 1. User Input Collection
- **PIN entry**: Secure PIN input (hidden characters)
- **File selection**: Browse and select input/output files
- **Parameter selection**: Dropdowns/lists for algorithm choices
- **Text input**: Labels, subjects, file paths

### 2. Enhanced UI Components
- **Forms**: Multi-field input forms for complex operations
- **Progress bars**: For long-running operations
- **Confirmation dialogs**: For destructive operations
- **File browser**: Navigate filesystem for file operations

### 3. State Management
- **Session persistence**: Remember token selection across commands
- **Input validation**: Real-time validation of user inputs
- **Error recovery**: Graceful handling of HSM errors
- **Multi-token support**: Select between multiple available tokens

### 4. Security Considerations
- **PIN handling**: Never log or display PINs in plaintext
- **Memory cleanup**: Secure clearing of sensitive data
- **Session timeouts**: Auto-logout for security
- **Audit trails**: Log security-relevant operations

## Implementation Strategy

### Phase 1: Complete Information & Status (IMMEDIATE)
1. Implement `execute_list_mechanisms_command()`
   - Use `pkcs11.get_mechanism_list()` and `get_mechanism_info()`
   - Format output with capabilities and constraints
2. Implement `execute_list_objects_command()`
   - Use `session.find_objects()` with no login (public objects only)
   - Show object types, labels, and handles
   - Add note about private objects requiring PIN

### Phase 2: Token Management (NEXT)
1. Add PIN input widgets (masked text input)
2. Implement token initialization workflow
3. Add confirmation dialogs for destructive operations

### Phase 3: Key Operations (FUTURE)
1. Design parameter selection UI (key types, sizes, etc.)
2. Implement key generation workflows
3. Add file I/O capabilities for export operations

### Phase 4: Cryptographic Operations (FUTURE)
1. Add file browser functionality
2. Implement signing/verification workflows
3. Add progress indicators for long operations

## Testing Status

### Verified Functionality
- ✅ TUI launches and renders correctly in Docker container
- ✅ Menu navigation works with arrow keys and Enter
- ✅ info command returns real PKCS#11 library information
- ✅ list-slots command shows real slot and token data
- ✅ Scrolling works for large outputs (146+ lines tested)
- ✅ Error handling gracefully displays failures
- ✅ Exit functionality (Q key) works properly

### Test Environment
- **Container**: Docker with SoftHSM2 and Kryoptic providers
- **Test data**: Multiple initialized tokens (TEST_SLOT_1 through TEST_SLOT_5)
- **HSM providers**: Both SoftHSM2 and Kryoptic validated
- **Output sizes**: Tested with 146-line slot listing (scrolling confirmed)

## Development Guidelines

### Code Organization
- Keep command execution methods focused and testable
- Use consistent error handling patterns
- Follow existing naming conventions (`execute_*_command`)
- Maintain separation between UI logic and PKCS#11 operations

### User Experience Principles
- Provide clear status feedback for all operations
- Use emojis and colors for visual clarity
- Show progress for operations that might take time
- Gracefully handle errors with helpful messages
- Maintain consistent navigation patterns

### Security Best Practices
- Never log PINs or sensitive data
- Clear sensitive data from memory when possible
- Use secure input methods for PINs
- Validate all user inputs
- Provide clear security warnings for dangerous operations

## Next Immediate Actions

1. **Implement list-mechanisms**: Add real mechanism enumeration to complete Information & Status
2. **Implement list-objects**: Add real object listing functionality  
3. **Add PIN input widget**: Create secure PIN entry for token operations
4. **Design form framework**: Plan multi-field input system for complex commands
5. **Create file browser**: Design file selection interface for I/O operations

The Interactive TUI is well-architected and functional for basic operations. The scrolling system works perfectly, and the foundation is solid for expanding to full PKCS#11 functionality.