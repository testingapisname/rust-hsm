/// PKCS#11 mechanism type constants and lookup
/// Based on PKCS#11 v2.40 specification
/// Get human-readable name for a mechanism type value
pub fn mechanism_name(val: u64) -> Option<&'static str> {
    match val {
        // RSA mechanisms
        0x00000000 => Some("CKM_RSA_PKCS_KEY_PAIR_GEN"),
        0x00000001 => Some("CKM_RSA_PKCS"),
        0x00000003 => Some("CKM_RSA_9796"),
        0x00000004 => Some("CKM_RSA_X_509"),
        0x00000005 => Some("CKM_MD2_RSA_PKCS"),
        0x00000006 => Some("CKM_MD5_RSA_PKCS"),
        0x00000007 => Some("CKM_SHA1_RSA_PKCS"),
        0x00000009 => Some("CKM_RIPEMD128_RSA_PKCS"),
        0x0000000a => Some("CKM_RIPEMD160_RSA_PKCS"),
        0x0000000c => Some("CKM_RSA_PKCS_OAEP"),
        0x0000000d => Some("CKM_RSA_X9_31_KEY_PAIR_GEN"),
        0x0000000e => Some("CKM_RSA_X9_31"),
        0x0000000f => Some("CKM_SHA1_RSA_X9_31"),

        // DSA mechanisms
        0x00000010 => Some("CKM_DSA_KEY_PAIR_GEN"),
        0x00000011 => Some("CKM_DSA"),
        0x00000012 => Some("CKM_DSA_SHA1"),
        0x00000013 => Some("CKM_DSA_SHA224"),
        0x00000014 => Some("CKM_DSA_SHA256"),
        0x00000015 => Some("CKM_DSA_SHA384"),
        0x00000016 => Some("CKM_DSA_SHA512"),

        // DH mechanisms
        0x00000020 => Some("CKM_DH_PKCS_KEY_PAIR_GEN"),
        0x00000021 => Some("CKM_DH_PKCS_DERIVE"),

        // DES mechanisms
        0x00000120 => Some("CKM_DES_KEY_GEN"),
        0x00000121 => Some("CKM_DES_ECB"),
        0x00000122 => Some("CKM_DES_CBC"),
        0x00000123 => Some("CKM_DES_MAC"),
        0x00000124 => Some("CKM_DES_MAC_GENERAL"),
        0x00000125 => Some("CKM_DES_CBC_PAD"),
        0x00000131 => Some("CKM_DES2_KEY_GEN"),
        0x00000132 => Some("CKM_DES3_KEY_GEN"),
        0x00000133 => Some("CKM_DES3_ECB"),
        0x00000134 => Some("CKM_DES3_CBC"),
        0x00000135 => Some("CKM_DES3_MAC"),
        0x00000136 => Some("CKM_DES3_MAC_GENERAL"),
        0x00000137 => Some("CKM_DES3_CBC_PAD"),

        // Hash mechanisms
        0x00000220 => Some("CKM_SHA_1"),
        0x00000250 => Some("CKM_SHA256"),
        0x00000251 => Some("CKM_SHA224"),
        0x00000255 => Some("CKM_SHA384"),
        0x00000256 => Some("CKM_SHA512"),
        0x00000260 => Some("CKM_SHA512_224"),
        0x00000261 => Some("CKM_SHA512_256"),

        // HMAC mechanisms
        0x00000221 => Some("CKM_SHA_1_HMAC"),
        0x00000222 => Some("CKM_SHA_1_HMAC_GENERAL"),
        0x00000257 => Some("CKM_SHA256_HMAC"),
        0x00000258 => Some("CKM_SHA256_HMAC_GENERAL"),
        0x00000259 => Some("CKM_SHA224_HMAC"),
        0x0000025a => Some("CKM_SHA224_HMAC_GENERAL"),
        0x0000025b => Some("CKM_SHA384_HMAC"),
        0x0000025c => Some("CKM_SHA384_HMAC_GENERAL"),
        0x0000025d => Some("CKM_SHA512_HMAC"),
        0x0000025e => Some("CKM_SHA512_HMAC_GENERAL"),
        0x00000262 => Some("CKM_SHA512_224_HMAC"),
        0x00000263 => Some("CKM_SHA512_224_HMAC_GENERAL"),
        0x00000264 => Some("CKM_SHA512_256_HMAC"),
        0x00000265 => Some("CKM_SHA512_256_HMAC_GENERAL"),

        // AES mechanisms
        0x00001080 => Some("CKM_AES_KEY_GEN"),
        0x00001081 => Some("CKM_AES_ECB"),
        0x00001082 => Some("CKM_AES_CBC"),
        0x00001083 => Some("CKM_AES_MAC"),
        0x00001084 => Some("CKM_AES_MAC_GENERAL"),
        0x00001085 => Some("CKM_AES_CBC_PAD"),
        0x00001086 => Some("CKM_AES_CTR"),
        0x00001087 => Some("CKM_AES_GCM"),
        0x00001088 => Some("CKM_AES_CCM"),
        0x00001089 => Some("CKM_AES_CTS"),
        0x00001090 => Some("CKM_AES_CMAC"),
        0x00001091 => Some("CKM_AES_CMAC_GENERAL"),
        0x00002109 => Some("CKM_AES_KEY_WRAP"),
        0x0000210a => Some("CKM_AES_KEY_WRAP_PAD"),

        // EC mechanisms
        0x00001040 => Some("CKM_EC_KEY_PAIR_GEN"),
        0x00001041 => Some("CKM_ECDSA"),
        0x00001042 => Some("CKM_ECDSA_SHA1"),
        0x00001043 => Some("CKM_ECDSA_SHA224"),
        0x00001044 => Some("CKM_ECDSA_SHA256"),
        0x00001045 => Some("CKM_ECDSA_SHA384"),
        0x00001046 => Some("CKM_ECDSA_SHA512"),
        0x00001050 => Some("CKM_ECDH1_DERIVE"),
        0x00001051 => Some("CKM_ECDH1_COFACTOR_DERIVE"),
        0x00001052 => Some("CKM_ECMQV_DERIVE"),

        // Generic secret key
        0x00000350 => Some("CKM_GENERIC_SECRET_KEY_GEN"),

        // Additional mechanisms found in SoftHSM
        0x0000108a => Some("CKM_AES_XCBC_MAC"),
        0x00001055 => Some("CKM_ECDH_AES_KEY_WRAP"),
        0x00001057 => Some("CKM_ECDH_X963_KDF"),
        0x00000270 => Some("CKM_SHA3_256"),
        0x00000271 => Some("CKM_SHA3_256_HMAC"),
        0x00001105 => Some("CKM_SP800_108_COUNTER_KDF"),

        // DSA mechanisms (0x0040-0x005f range)
        0x00000040 => Some("CKM_DSA_PARAMETER_GEN"),
        0x00000041 => Some("CKM_DSA_PROBABLISTIC_PARAMETER_GEN"),
        0x00000042 => Some("CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN"),
        0x00000043 => Some("CKM_DSA_FIPS_G_GEN"),
        0x00000044 => Some("CKM_AES_OFB"),
        0x00000045 => Some("CKM_AES_CFB64"),

        _ => None,
    }
}

/// Get category for a mechanism
pub fn mechanism_category(val: u64) -> &'static str {
    match val {
        0x0000..=0x001f => "RSA",
        0x0020..=0x003f => "DH",
        0x0040..=0x005f => "DSA",
        0x0120..=0x013f => "DES/3DES",
        0x0220..=0x027f => "Hash/HMAC",
        0x0350..=0x036f => "Generic Secret",
        0x1040..=0x105f => "ECDSA/ECDH",
        0x1080..=0x10ff => "AES",
        0x2109..=0x210a => "AES Key Wrap",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_mechanisms() {
        assert_eq!(mechanism_name(0x0000), Some("CKM_RSA_PKCS_KEY_PAIR_GEN"));
        assert_eq!(mechanism_name(0x0001), Some("CKM_RSA_PKCS"));
        assert_eq!(mechanism_name(0x0006), Some("CKM_MD5_RSA_PKCS"));
        assert_eq!(mechanism_category(0x0000), "RSA");
        assert_eq!(mechanism_category(0x0001), "RSA");
    }

    #[test]
    fn test_aes_mechanisms() {
        assert_eq!(mechanism_name(0x1080), Some("CKM_AES_KEY_GEN"));
        assert_eq!(mechanism_name(0x1081), Some("CKM_AES_ECB"));
        assert_eq!(mechanism_name(0x1087), Some("CKM_AES_GCM"));
        assert_eq!(mechanism_category(0x1080), "AES");
        assert_eq!(mechanism_category(0x1087), "AES");
    }

    #[test]
    fn test_hash_mechanisms() {
        assert_eq!(mechanism_name(0x0220), Some("CKM_SHA_1"));
        assert_eq!(mechanism_name(0x0250), Some("CKM_SHA256"));
        assert_eq!(mechanism_name(0x0256), Some("CKM_SHA512"));
        assert_eq!(mechanism_category(0x0220), "Hash/HMAC");
    }

    #[test]
    fn test_hmac_mechanisms() {
        assert_eq!(mechanism_name(0x0221), Some("CKM_SHA_1_HMAC"));
        assert_eq!(mechanism_name(0x0257), Some("CKM_SHA256_HMAC"));
        assert_eq!(mechanism_category(0x0221), "Hash/HMAC");
    }

    #[test]
    fn test_ecdsa_mechanisms() {
        assert_eq!(mechanism_name(0x1040), Some("CKM_EC_KEY_PAIR_GEN"));
        assert_eq!(mechanism_name(0x1041), Some("CKM_ECDSA"));
        assert_eq!(mechanism_name(0x1042), Some("CKM_ECDSA_SHA1"));
        assert_eq!(mechanism_category(0x1040), "ECDSA/ECDH");
    }

    #[test]
    fn test_des_mechanisms() {
        assert_eq!(mechanism_name(0x0131), Some("CKM_DES2_KEY_GEN"));
        assert_eq!(mechanism_name(0x0132), Some("CKM_DES3_KEY_GEN"));
        assert_eq!(mechanism_category(0x0131), "DES/3DES");
    }

    #[test]
    fn test_key_wrap_mechanisms() {
        assert_eq!(mechanism_name(0x2109), Some("CKM_AES_KEY_WRAP"));
        assert_eq!(mechanism_name(0x210a), Some("CKM_AES_KEY_WRAP_PAD"));
        assert_eq!(mechanism_category(0x2109), "AES Key Wrap");
    }

    #[test]
    fn test_unknown_mechanism() {
        assert_eq!(mechanism_name(0x9999), None);
        assert_eq!(mechanism_category(0x9999), "Other");
    }

    #[test]
    fn test_generic_secret() {
        assert_eq!(mechanism_name(0x0350), Some("CKM_GENERIC_SECRET_KEY_GEN"));
        assert_eq!(mechanism_category(0x0350), "Generic Secret");
    }

    #[test]
    fn test_dh_category() {
        assert_eq!(mechanism_category(0x0020), "DH");
        assert_eq!(mechanism_category(0x0021), "DH");
    }

    #[test]
    fn test_dsa_category() {
        assert_eq!(mechanism_category(0x0040), "DSA");
        assert_eq!(mechanism_category(0x0050), "DSA");
    }
}
