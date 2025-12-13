use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use anyhow::{Context, Result};
use tracing::info;

use super::keys::find_token_slot;

#[derive(Debug)]
struct SecurityIssue {
    key_label: String,
    handle: String,
    key_class: String,
    issue_type: IssueType,
}

#[derive(Debug, PartialEq)]
enum IssueType {
    ExtractablePrivateKey,
    NonSensitivePrivateKey,
    NotAlwaysSensitive,
    ExtractableAfterCreation,
    ModifiablePrivateKey,
    MissingPrivateKey,
    MissingPublicKey,
}

impl IssueType {
    fn severity(&self) -> &str {
        match self {
            IssueType::ExtractablePrivateKey => "CRITICAL",
            IssueType::NonSensitivePrivateKey => "CRITICAL",
            IssueType::NotAlwaysSensitive => "HIGH",
            IssueType::ExtractableAfterCreation => "HIGH",
            IssueType::ModifiablePrivateKey => "MEDIUM",
            IssueType::MissingPrivateKey => "LOW",
            IssueType::MissingPublicKey => "LOW",
        }
    }

    fn description(&self) -> &str {
        match self {
            IssueType::ExtractablePrivateKey => "Private key is extractable (can be exported)",
            IssueType::NonSensitivePrivateKey => "Private key is not sensitive (can be read)",
            IssueType::NotAlwaysSensitive => "Private key was not always sensitive",
            IssueType::ExtractableAfterCreation => "Private key was not always non-extractable",
            IssueType::ModifiablePrivateKey => "Private key attributes are modifiable",
            IssueType::MissingPrivateKey => "Public key found without matching private key",
            IssueType::MissingPublicKey => "Private key found without matching public key",
        }
    }
}

pub fn audit_keys(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;
    
    pkcs11.initialize(CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot = find_token_slot(&pkcs11, token_label)?;
    
    info!("Running security audit on token '{}'", token_label);

    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;

    // Find all key objects
    let all_objects = session.find_objects(&[])?;
    
    let mut issues: Vec<SecurityIssue> = Vec::new();
    let mut stats = AuditStats::default();

    println!("\n{}", "=".repeat(80));
    println!("HSM SECURITY AUDIT");
    println!("{}", "=".repeat(80));
    println!("Token: {}", token_label);
    println!("Scanning {} objects...\n", all_objects.len());

    for handle in &all_objects {
        if let Ok(attrs) = session.get_attributes(*handle, &[
            AttributeType::Class,
            AttributeType::Label,
            AttributeType::Private,
            AttributeType::Sensitive,
            AttributeType::Extractable,
            AttributeType::Modifiable,
            AttributeType::AlwaysSensitive,
            AttributeType::NeverExtractable,
        ]) {
            let mut obj_class = None;
            let mut label = String::from("(unlabeled)");
            let mut is_private = false;
            let mut is_sensitive = false;
            let mut is_extractable = false;
            let mut is_modifiable = false;
            let mut always_sensitive = false;
            let mut never_extractable = false;

            for attr in &attrs {
                match attr {
                    Attribute::Class(c) => obj_class = Some(*c),
                    Attribute::Label(l) => {
                        if let Ok(s) = String::from_utf8(l.clone()) {
                            label = s;
                        }
                    }
                    Attribute::Private(b) => is_private = *b,
                    Attribute::Sensitive(b) => is_sensitive = *b,
                    Attribute::Extractable(b) => is_extractable = *b,
                    Attribute::Modifiable(b) => is_modifiable = *b,
                    Attribute::AlwaysSensitive(b) => always_sensitive = *b,
                    Attribute::NeverExtractable(b) => never_extractable = *b,
                    _ => {}
                }
            }

            if let Some(class) = obj_class {
                let class_name = format!("{:?}", class);
                
                // Check for private keys
                if class == ObjectClass::PRIVATE_KEY {
                    stats.private_keys += 1;
                    
                    // Check for security issues
                    if is_extractable {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            issue_type: IssueType::ExtractablePrivateKey,
                        });
                        stats.extractable_private += 1;
                    }
                    
                    if !is_sensitive {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            issue_type: IssueType::NonSensitivePrivateKey,
                        });
                        stats.non_sensitive_private += 1;
                    }
                    
                    if !always_sensitive && is_sensitive {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            issue_type: IssueType::NotAlwaysSensitive,
                        });
                    }
                    
                    if !never_extractable && !is_extractable {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            issue_type: IssueType::ExtractableAfterCreation,
                        });
                    }
                    
                    if is_modifiable {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            issue_type: IssueType::ModifiablePrivateKey,
                        });
                    }
                } else if class == ObjectClass::PUBLIC_KEY {
                    stats.public_keys += 1;
                } else if class == ObjectClass::SECRET_KEY {
                    stats.secret_keys += 1;
                    
                    // Check secret key security
                    if is_extractable {
                        stats.extractable_secret += 1;
                    }
                }
            }
        }
    }

    // Print statistics
    println!("SUMMARY");
    println!("{}", "-".repeat(80));
    println!("Total Objects:        {}", all_objects.len());
    println!("Private Keys:         {}", stats.private_keys);
    println!("Public Keys:          {}", stats.public_keys);
    println!("Secret Keys:          {}", stats.secret_keys);
    println!();
    
    // Print security issues
    if issues.is_empty() {
        println!("✅ No security issues found!");
    } else {
        println!("⚠️  SECURITY ISSUES FOUND: {}", issues.len());
        println!();
        
        // Group by severity
        let critical: Vec<_> = issues.iter().filter(|i| i.issue_type.severity() == "CRITICAL").collect();
        let high: Vec<_> = issues.iter().filter(|i| i.issue_type.severity() == "HIGH").collect();
        let medium: Vec<_> = issues.iter().filter(|i| i.issue_type.severity() == "MEDIUM").collect();
        let low: Vec<_> = issues.iter().filter(|i| i.issue_type.severity() == "LOW").collect();
        
        if !critical.is_empty() {
            println!("🔴 CRITICAL ({})", critical.len());
            println!("{}", "-".repeat(80));
            for issue in critical {
                print_issue(issue);
            }
            println!();
        }
        
        if !high.is_empty() {
            println!("🟠 HIGH ({})", high.len());
            println!("{}", "-".repeat(80));
            for issue in high {
                print_issue(issue);
            }
            println!();
        }
        
        if !medium.is_empty() {
            println!("🟡 MEDIUM ({})", medium.len());
            println!("{}", "-".repeat(80));
            for issue in medium {
                print_issue(issue);
            }
            println!();
        }
        
        if !low.is_empty() {
            println!("🔵 LOW ({})", low.len());
            println!("{}", "-".repeat(80));
            for issue in low {
                print_issue(issue);
            }
            println!();
        }
    }
    
    println!("{}", "=".repeat(80));
    
    // Return error if critical or high issues found
    if !issues.is_empty() {
        let critical_count = issues.iter().filter(|i| i.issue_type.severity() == "CRITICAL").count();
        let high_count = issues.iter().filter(|i| i.issue_type.severity() == "HIGH").count();
        
        if critical_count > 0 || high_count > 0 {
            anyhow::bail!("Security audit failed: {} critical, {} high severity issues found", 
                critical_count, high_count);
        }
    }

    Ok(())
}

fn print_issue(issue: &SecurityIssue) {
    println!("  Key: '{}' ({})", issue.key_label, issue.key_class);
    println!("    Issue: {}", issue.issue_type.description());
    println!("    Handle: {}", issue.handle);
}

#[derive(Default)]
struct AuditStats {
    private_keys: usize,
    public_keys: usize,
    secret_keys: usize,
    extractable_private: usize,
    non_sensitive_private: usize,
    extractable_secret: usize,
}
