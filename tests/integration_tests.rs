//! Comprehensive end-to-end integration tests for fritzdecode.

use std::{fs, io::Cursor};

use fritzdecode::{
    avm_cfg::{parse_avm_cfg, to_json_string, to_yaml_string},
    crack::crack_wordlist,
    crypto::{self, IsStringValue, PasswordTester},
    diff::diff_backups,
    errors::Error,
    pack::{pack_backup, unpack_backup},
    passwords::ExtractedCredentials,
    ConfigBackup, File, FileContent,
};

fn create_synthetic_backup() -> ConfigBackup<fritzdecode::markers::Verified> {
    let ar7_text = r#"
meta { encoding = "utf-8"; }
ar7cfg {
    mode = dsldmode_router;
    active_provider = "SyntheticFiber";
    targets {
        name = "internet";
        local {
            username = "fiber_user_001";
            passwd = "TopSecretPppoePassword";
        }
    }
}
"#;

    let voip_text = r#"
meta { encoding = "utf-8"; }
voipcfg {
    ua1 {
        name = "VoipLine1";
        username = "055123456";
        passwd = "VoipSecretPassword99";
        registrar = "sip.fiber.example.com";
    }
}
"#;

    let wlan_text = r#"
meta { encoding = "utf-8"; }
wlancfg {
    ssid = "SyntheticHomeWifi";
    pskvalue = "SuperStrongWifiKey2026!";
    ssid_scnd = "Synthetic5GHz";
    pskvalue_scnd = "SuperStrongWifiKey2026!";
}
"#;

    let binary_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];

    let files = vec![
        File {
            name: "ar7.cfg".to_string(),
            content: FileContent::Plain(ar7_text.to_string()),
        },
        File {
            name: "voip.cfg".to_string(),
            content: FileContent::Plain(voip_text.to_string()),
        },
        File {
            name: "wlan.cfg".to_string(),
            content: FileContent::Plain(wlan_text.to_string()),
        },
        File {
            name: "custom_binary.bin".to_string(),
            content: FileContent::Binary(binary_bytes),
        },
    ];

    let properties = vec![
        ("FirmwareVersion".to_string(), "260.07.57".to_string()),
        ("Country".to_string(), "039".to_string()),
        ("Language".to_string(), "it".to_string()),
    ];

    let unverified =
        ConfigBackup::from_parts("FRITZ!Box 7590 AX".to_string(), properties, files, 0);

    unverified.update_crc()
}

#[test]
fn test_encryption_decryption_lifecycle() {
    let backup = create_synthetic_backup();
    let original_crc = backup.crc();
    assert_ne!(original_crc, 0);

    // 1. Encrypt with password
    let password = "TestMasterPassword123!";
    let encrypted = backup.encrypt(password).expect("Encryption failed");
    let encrypted_verified = encrypted.update_crc();

    // Verify secrets are now encrypted ($$$$)
    let mut found_encrypted_secret = false;
    for file in encrypted_verified.files() {
        if let FileContent::Plain(content) = &file.content {
            if content.contains("$$$$") {
                found_encrypted_secret = true;
            }
            // Cleartext passwords should NOT be present in plaintext
            assert!(!content.contains("TopSecretPppoePassword"));
            assert!(!content.contains("VoipSecretPassword99"));
            assert!(!content.contains("SuperStrongWifiKey2026!"));
        }
    }
    assert!(
        found_encrypted_secret,
        "Expected encrypted secrets with $$$$ prefix"
    );

    // 2. Serialize encrypted backup
    let mut serialized_bytes = Vec::new();
    encrypted_verified
        .serialize(&mut serialized_bytes)
        .expect("Serialization failed");

    // 3. Load from bytes and verify CRC
    let loaded = ConfigBackup::load(Cursor::new(&serialized_bytes))
        .expect("Failed to load serialized backup");
    let verified = loaded.verify_crc().expect("Loaded backup failed CRC check");

    // 4. Decrypt with correct password
    let decrypted = verified.decrypt(password).expect("Decryption failed");

    // Verify cleartext values are restored
    for file in decrypted.files() {
        if let FileContent::Plain(content) = &file.content {
            match file.name.as_str() {
                "ar7.cfg" => assert!(content.contains("TopSecretPppoePassword")),
                "voip.cfg" => assert!(content.contains("VoipSecretPassword99")),
                "wlan.cfg" => assert!(content.contains("SuperStrongWifiKey2026!")),
                _ => {}
            }
        }
    }

    // 5. Test credential extraction
    let creds = ExtractedCredentials::extract(&decrypted);
    assert_eq!(creds.model, "FRITZ!Box 7590 AX");
    assert_eq!(creds.internet.len(), 1);
    assert_eq!(creds.internet[0].username, "fiber_user_001");
    assert_eq!(creds.internet[0].password, "TopSecretPppoePassword");
    assert_eq!(creds.voip.len(), 1);
    assert_eq!(creds.voip[0].password, "VoipSecretPassword99");
    assert_eq!(creds.wifi.len(), 2);
    assert_eq!(creds.wifi[0].ssid, "SyntheticHomeWifi");
    assert_eq!(creds.wifi[0].psk, "SuperStrongWifiKey2026!");
    assert_eq!(creds.wifi[1].ssid, "Synthetic5GHz");
    assert_eq!(creds.wifi[1].psk, "SuperStrongWifiKey2026!");
}

#[test]
fn test_wrong_password_fails_decryption() {
    let backup = create_synthetic_backup();
    let encrypted = backup.encrypt("CorrectPassword").unwrap().update_crc();

    let mut buf = Vec::new();
    encrypted.serialize(&mut buf).unwrap();

    let loaded = ConfigBackup::load(Cursor::new(buf)).unwrap();
    let res = loaded.decrypt("IncorrectPassword");

    assert!(
        res.is_err(),
        "Expected decryption to fail with incorrect password"
    );
    match res.err().unwrap() {
        Error::Decryption(_) | Error::FormatError(_) => {}
        other => panic!("Unexpected error type: {other:?}"),
    }
}

#[test]
fn test_crc_tamper_detection() {
    let backup = create_synthetic_backup();
    let mut buf = Vec::new();
    backup.serialize(&mut buf).unwrap();

    // Tamper with content (replace 'Fiber' with 'Cable')
    let mut tampered = String::from_utf8(buf).unwrap();
    tampered = tampered.replace("SyntheticFiber", "SyntheticCable");

    let loaded = ConfigBackup::load(Cursor::new(tampered.as_bytes())).unwrap();
    let res = loaded.verify_crc();

    assert!(res.is_err(), "Expected tampered content to fail CRC check");
}

#[test]
fn test_unpack_and_pack_cycle() {
    let backup = create_synthetic_backup();
    let temp_dir = std::env::temp_dir().join("fritzdecode_test_unpack_pack");
    let _ = fs::remove_dir_all(&temp_dir);

    // 1. Unpack to directory
    unpack_backup(&backup, &temp_dir).expect("Unpack failed");
    assert!(temp_dir.join("manifest.json").exists());
    assert!(temp_dir.join("ar7.cfg").exists());
    assert!(temp_dir.join("custom_binary.bin").exists());

    // 2. Pack back from directory
    let repacked = pack_backup(&temp_dir).expect("Pack failed");
    assert_eq!(repacked.model(), backup.model());
    assert_eq!(repacked.files().len(), backup.files().len());

    // Verify CRC of repacked backup
    let mut out_buf = Vec::new();
    repacked
        .serialize(&mut out_buf)
        .expect("Serialization failed");

    let loaded = ConfigBackup::load(Cursor::new(out_buf)).unwrap();
    assert!(
        loaded.verify_crc().is_ok(),
        "Repacked backup must have a valid CRC"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_avm_cfg_to_json_and_yaml() {
    let cfg_text = r#"
    meta { encoding = "utf-8"; }
    section {
        name = "test_section";
        enabled = yes;
        max_limit = 100;
        servers = "srv1.example.com", "srv2.example.com";
        nested {
            flag = no;
        }
    }
    "#;

    let value = parse_avm_cfg(cfg_text);
    assert_eq!(value["section"]["name"], "test_section");
    assert_eq!(value["section"]["enabled"], true);
    assert_eq!(value["section"]["max_limit"], 100);
    assert_eq!(value["section"]["servers"][0], "srv1.example.com");
    assert_eq!(value["section"]["servers"][1], "srv2.example.com");
    assert_eq!(value["section"]["nested"]["flag"], false);

    let json_str = to_json_string(&value).expect("JSON serialization failed");
    assert!(json_str.contains("\"enabled\": true"));

    let yaml_str = to_yaml_string(&value).expect("YAML serialization failed");
    assert!(yaml_str.contains("enabled: true"));
}

#[test]
fn test_standalone_secret_encryption_decryption() {
    let secret = "MyStandaloneSecretPhrase2026!";
    let password = "EncryptionKeyXYZ";

    let bootstrap_key = crypto::generate_boostrap_key(password);
    let encrypted = crypto::encode_secret(
        secret.as_bytes().to_vec(),
        bootstrap_key,
        IsStringValue::Yes,
    )
    .expect("Failed to encode secret");

    assert!(encrypted.starts_with("$$$$"));

    let decrypted_bytes = crypto::decode_secret(&encrypted, bootstrap_key, IsStringValue::Yes)
        .expect("Failed to decode secret");

    assert_eq!(String::from_utf8(decrypted_bytes).unwrap(), secret);
}

#[test]
fn test_diff_between_backups() {
    let b1 = create_synthetic_backup();

    let mut b2_files = b1.files().to_vec();
    // Modify ar7.cfg
    if let Some(f) = b2_files.iter_mut().find(|f| f.name == "ar7.cfg") {
        f.content = FileContent::Plain(
            r#"
meta { encoding = "utf-8"; }
ar7cfg {
    mode = dsldmode_bridge;
    active_provider = "SyntheticFiberV2";
}
"#
            .to_string(),
        );
    }
    // Add a new file
    b2_files.push(File {
        name: "new_vpn.cfg".to_string(),
        content: FileContent::Plain("vpncfg { enabled = yes; }".to_string()),
    });

    let mut b2_props = b1.properties().to_vec();
    b2_props.push(("NewKey".to_string(), "NewValue".to_string()));

    let b2 = ConfigBackup::from_parts(b1.model().to_string(), b2_props, b2_files, 0).update_crc();

    // 1. Full diff
    let full_diff = diff_backups(&b1, &b2, None);
    assert!(full_diff.contains("+ NewKey=NewValue"));
    assert!(full_diff.contains("--- ar7.cfg"));
    assert!(full_diff.contains("+++ ar7.cfg"));
    assert!(full_diff.contains("-    mode = dsldmode_router;"));
    assert!(full_diff.contains("+    mode = dsldmode_bridge;"));
    assert!(full_diff.contains("Added file: new_vpn.cfg"));

    // 2. Section filtered diff
    let section_diff = diff_backups(&b1, &b2, Some("ar7.cfg"));
    assert!(section_diff.contains("--- ar7.cfg"));
    assert!(!section_diff.contains("NewKey=NewValue"));
    assert!(!section_diff.contains("new_vpn.cfg"));
}

#[test]
fn test_offline_password_cracking() {
    let backup = create_synthetic_backup();
    let target_pwd = "FritzMasterKey2026";
    let encrypted = backup.encrypt(target_pwd).expect("Encryption failed");

    let encrypted_key = encrypted
        .encrypted_password()
        .expect("Missing encrypted password property");

    let tester = PasswordTester::new(encrypted_key).expect("Valid PasswordTester");

    // Dictionary with candidate words
    let wordlist = "admin\n12345678\npassword\nFritzMasterKey2026\nletmein\n";
    let stats = crack_wordlist(&tester, Cursor::new(wordlist), Some(2), None);

    assert_eq!(stats.found.as_deref(), Some(target_pwd));
    assert!(stats.candidates_tested >= 4);

    // Negative case
    let wrong_wordlist = "wrong1\nwrong2\nwrong3\n";
    let stats_fail = crack_wordlist(&tester, Cursor::new(wrong_wordlist), Some(1), None);
    assert_eq!(stats_fail.found, None);
    assert_eq!(stats_fail.candidates_tested, 3);
}

#[test]
fn test_legacy_charset_matrix() {
    // Test handling of ISO-8859-1 accented characters in export files (common in Fritz!OS 6.x/7.0)
    let latin1_content = b"**** FRITZ!Box 7490 CONFIGURATION EXPORT\nFirmwareVersion=113.06.87\nCountry=049\nLanguage=de\n**** CFGFILE:ar7.cfg\nmeta { encoding = \"iso-8859-1\"; }\nar7cfg {\n    targets {\n        passwd = \"M\xfcnchen-Caf\xe9-2024!\";\n    }\n}\n**** END OF FILE ****\n**** CFGFILE:wlan.cfg\nwlancfg {\n    ssid = \"WLAN-\xd6sterreich\";\n    pskvalue = \"Str\xdf-123456\";\n}\n**** END OF FILE ****\n**** END OF EXPORT 12345678 ****\n";

    let loaded =
        ConfigBackup::load(Cursor::new(latin1_content)).expect("Failed to load latin1 backup");
    let ar7_file = loaded.files().iter().find(|f| f.name == "ar7.cfg").unwrap();
    if let FileContent::Plain(text) = &ar7_file.content {
        assert!(text.contains("München-Café-2024!"));
    } else {
        panic!("Expected plain text file");
    }

    let creds = ExtractedCredentials::extract(&loaded);
    let wifi = creds
        .wifi
        .iter()
        .find(|w| w.ssid.contains("Österreich"))
        .unwrap();
    assert_eq!(wifi.psk, "Strß-123456");
}
