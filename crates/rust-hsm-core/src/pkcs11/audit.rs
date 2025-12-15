use anyhow::{Context, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use tracing::info;

use super::keys::find_token_slot;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct SecurityIssue {
    key_label: String,
    handle: String,
    key_class: String,
    key_type: String,
    issue_type: IssueType,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    json_output: bool,
) -> Result<()> {
    audit_keys_internal(module_path, token_label, user_pin, false, json_output)
}

fn audit_keys_internal(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    _verbose: bool,
    json_output: bool,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(CInitializeArgs::OsThreads)
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
        if let Ok(attrs) = session.get_attributes(
            *handle,
            &[
                AttributeType::Class,
                AttributeType::KeyType,
                AttributeType::Label,
                AttributeType::Private,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Modifiable,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
                AttributeType::ModulusBits,
                AttributeType::EcParams,
                AttributeType::ValueLen,
            ],
        ) {
            let mut obj_class = None;
            let mut key_type_attr = None;
            let mut label = String::from("(unlabeled)");
            let mut _is_private = false;
            let mut is_sensitive = false;
            let mut is_extractable = false;
            let mut is_modifiable = false;
            let mut always_sensitive = false;
            let mut never_extractable = false;
            let mut modulus_bits = None;
            let mut ec_params = None;
            let mut value_len = None;

            for attr in &attrs {
                match attr {
                    Attribute::Class(c) => obj_class = Some(*c),
                    Attribute::KeyType(kt) => key_type_attr = Some(*kt),
                    Attribute::Label(l) => {
                        if let Ok(s) = String::from_utf8(l.clone()) {
                            label = s;
                        }
                    }
                    Attribute::Private(b) => _is_private = *b,
                    Attribute::Sensitive(b) => is_sensitive = *b,
                    Attribute::Extractable(b) => is_extractable = *b,
                    Attribute::Modifiable(b) => is_modifiable = *b,
                    Attribute::AlwaysSensitive(b) => always_sensitive = *b,
                    Attribute::NeverExtractable(b) => never_extractable = *b,
                    Attribute::ModulusBits(bits) => modulus_bits = Some(*bits),
                    Attribute::EcParams(params) => ec_params = Some(params.clone()),
                    Attribute::ValueLen(len) => value_len = Some(*len),
                    _ => {}
                }
            }

            if let Some(class) = obj_class {
                let class_name = match class {
                    ObjectClass::PUBLIC_KEY => "PUBLIC_KEY",
                    ObjectClass::PRIVATE_KEY => "PRIVATE_KEY",
                    ObjectClass::SECRET_KEY => "SECRET_KEY",
                    _ => "UNKNOWN",
                }
                .to_string();

                // Determine key type with size
                let key_type =
                    determine_key_type(key_type_attr, modulus_bits, ec_params.as_ref(), value_len);

                // Check for private keys
                if class == ObjectClass::PRIVATE_KEY {
                    stats.private_keys += 1;

                    // Check for security issues
                    if is_extractable {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            key_type: key_type.clone(),
                            issue_type: IssueType::ExtractablePrivateKey,
                        });
                        stats.extractable_private += 1;
                    }

                    if !is_sensitive {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            key_type: key_type.clone(),
                            issue_type: IssueType::NonSensitivePrivateKey,
                        });
                        stats.non_sensitive_private += 1;
                    }

                    if !always_sensitive && is_sensitive {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            key_type: key_type.clone(),
                            issue_type: IssueType::NotAlwaysSensitive,
                        });
                    }

                    if !never_extractable && !is_extractable {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            key_type: key_type.clone(),
                            issue_type: IssueType::ExtractableAfterCreation,
                        });
                    }

                    if is_modifiable {
                        issues.push(SecurityIssue {
                            key_label: label.clone(),
                            handle: format!("{:?}", handle),
                            key_class: class_name.clone(),
                            key_type: key_type.clone(),
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
        // Group issues by key
        use std::collections::HashMap;
        let mut issues_by_key: HashMap<String, Vec<&SecurityIssue>> = HashMap::new();
        for issue in &issues {
            issues_by_key
                .entry(issue.key_label.clone())
                .or_default()
                .push(issue);
        }

        let unique_keys = issues_by_key.len();
        println!(
            "⚠️  SECURITY ISSUES FOUND: {} issue(s) across {} key(s)",
            issues.len(),
            unique_keys
        );
        println!();

        // Group by severity
        let critical: Vec<_> = issues
            .iter()
            .filter(|i| i.issue_type.severity() == "CRITICAL")
            .collect();
        let high: Vec<_> = issues
            .iter()
            .filter(|i| i.issue_type.severity() == "HIGH")
            .collect();
        let medium: Vec<_> = issues
            .iter()
            .filter(|i| i.issue_type.severity() == "MEDIUM")
            .collect();
        let low: Vec<_> = issues
            .iter()
            .filter(|i| i.issue_type.severity() == "LOW")
            .collect();

        if !critical.is_empty() {
            println!("🔴 CRITICAL ({} issues)", critical.len());
            println!("{}", "-".repeat(80));
            print_grouped_issues(critical);
        }

        if !high.is_empty() {
            println!("🟠 HIGH ({} issues)", high.len());
            println!("{}", "-".repeat(80));
            print_grouped_issues(high);
        }

        if !medium.is_empty() {
            println!("🟡 MEDIUM ({} issues)", medium.len());
            println!("{}", "-".repeat(80));
            print_grouped_issues(medium);
        }

        if !low.is_empty() {
            println!("🔵 LOW ({} issues)", low.len());
            println!("{}", "-".repeat(80));
            print_grouped_issues(low);
        }
    }

    println!("{}", "=".repeat(80));

    if json_output {
        // JSON output
        output_json_audit(token_label, all_objects.len(), &stats, &issues)?;
    }

    // Return error if critical or high issues found
    if !issues.is_empty() {
        let critical_count = issues
            .iter()
            .filter(|i| i.issue_type.severity() == "CRITICAL")
            .count();
        let high_count = issues
            .iter()
            .filter(|i| i.issue_type.severity() == "HIGH")
            .count();

        if critical_count > 0 || high_count > 0 {
            anyhow::bail!(
                "Security audit failed: {} critical, {} high severity issues found",
                critical_count,
                high_count
            );
        }
    }

    Ok(())
}

fn print_grouped_issues(issues: Vec<&SecurityIssue>) {
    use std::collections::HashMap;

    // Group by key
    let mut by_key: HashMap<String, Vec<&SecurityIssue>> = HashMap::new();
    for issue in issues {
        by_key
            .entry(issue.key_label.clone())
            .or_insert_with(Vec::new)
            .push(issue);
    }

    for (key_label, key_issues) in by_key {
        // Use first issue for key metadata
        let first = key_issues[0];

        if key_issues.len() == 1 {
            println!("  📌 Key: '{}' [{}]", key_label, first.key_type);
        } else {
            println!(
                "  📌 Key: '{}' [{}] - {} issues",
                key_label,
                first.key_type,
                key_issues.len()
            );
        }

        println!("     Type: {}", first.key_class);
        println!("     Handle: {}", first.handle);

        if key_issues.len() == 1 {
            println!("     Issue: {}", first.issue_type.description());
            println!(
                "     Recommendation: {}",
                get_recommendation(&first.issue_type)
            );
        } else {
            println!("     Issues:");
            for (idx, issue) in key_issues.iter().enumerate() {
                println!("       {}. {}", idx + 1, issue.issue_type.description());
                println!("          → {}", get_recommendation(&issue.issue_type));
            }
        }
        println!();
    }
}

fn get_recommendation(issue_type: &IssueType) -> &str {
    match issue_type {
        IssueType::ExtractablePrivateKey => {
            "Private keys should NEVER be extractable in production"
        }
        IssueType::NonSensitivePrivateKey => "Private keys must always be marked as sensitive",
        IssueType::NotAlwaysSensitive => {
            "Private key was created without CKA_ALWAYS_SENSITIVE=true"
        }
        IssueType::ExtractableAfterCreation => {
            "Private key was created without CKA_NEVER_EXTRACTABLE=true"
        }
        IssueType::ModifiablePrivateKey => {
            "Consider making private keys non-modifiable for immutability"
        }
        IssueType::MissingPrivateKey => "Verify if public key has a corresponding private key",
        IssueType::MissingPublicKey => "Consider exporting public key for sharing/verification",
    }
}

fn determine_key_type(
    key_type: Option<cryptoki::object::KeyType>,
    modulus_bits: Option<cryptoki::types::Ulong>,
    ec_params: Option<&Vec<u8>>,
    value_len: Option<cryptoki::types::Ulong>,
) -> String {
    use cryptoki::object::KeyType;

    if let Some(kt) = key_type {
        match kt {
            KeyType::RSA => {
                if let Some(bits) = modulus_bits {
                    format!("RSA-{}", *bits)
                } else {
                    "RSA".to_string()
                }
            }
            KeyType::EC => {
                if let Some(params) = ec_params {
                    match params.as_slice() {
                        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => {
                            "ECDSA P-256".to_string()
                        }
                        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => "ECDSA P-384".to_string(),
                        _ => "ECDSA".to_string(),
                    }
                } else {
                    "ECDSA".to_string()
                }
            }
            KeyType::AES => {
                if let Some(len) = value_len {
                    format!("AES-{}", *len * 8)
                } else {
                    "AES".to_string()
                }
            }
            KeyType::GENERIC_SECRET => "HMAC".to_string(),
            _ => format!("{:?}", kt),
        }
    } else {
        "Unknown".to_string()
    }
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

fn output_json_audit(
    token_label: &str,
    total_objects: usize,
    stats: &AuditStats,
    issues: &[SecurityIssue],
) -> Result<()> {
    #[derive(Serialize)]
    struct AuditReport {
        token: String,
        total_objects: usize,
        private_keys: usize,
        public_keys: usize,
        secret_keys: usize,
        issues: Vec<AuditIssue>,
        summary: AuditSummary,
    }

    #[derive(Serialize)]
    struct AuditIssue {
        key_label: String,
        handle: String,
        key_class: String,
        key_type: String,
        severity: String,
        issue_type: String,
        description: String,
        recommendation: String,
    }

    #[derive(Serialize)]
    struct AuditSummary {
        total_issues: usize,
        critical_count: usize,
        high_count: usize,
        medium_count: usize,
        low_count: usize,
        unique_keys_affected: usize,
    }

    use std::collections::HashSet;
    let unique_keys: HashSet<_> = issues.iter().map(|i| &i.key_label).collect();

    let critical_count = issues
        .iter()
        .filter(|i| i.issue_type.severity() == "CRITICAL")
        .count();
    let high_count = issues
        .iter()
        .filter(|i| i.issue_type.severity() == "HIGH")
        .count();
    let medium_count = issues
        .iter()
        .filter(|i| i.issue_type.severity() == "MEDIUM")
        .count();
    let low_count = issues
        .iter()
        .filter(|i| i.issue_type.severity() == "LOW")
        .count();

    let report = AuditReport {
        token: token_label.to_string(),
        total_objects,
        private_keys: stats.private_keys,
        public_keys: stats.public_keys,
        secret_keys: stats.secret_keys,
        issues: issues
            .iter()
            .map(|i| AuditIssue {
                key_label: i.key_label.clone(),
                handle: i.handle.clone(),
                key_class: i.key_class.clone(),
                key_type: i.key_type.clone(),
                severity: i.issue_type.severity().to_string(),
                issue_type: format!("{:?}", i.issue_type),
                description: i.issue_type.description().to_string(),
                recommendation: get_recommendation(&i.issue_type).to_string(),
            })
            .collect(),
        summary: AuditSummary {
            total_issues: issues.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            unique_keys_affected: unique_keys.len(),
        },
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
