window.BENCHMARK_DATA = {
  "lastUpdate": 1777172965789,
  "repoUrl": "https://github.com/testingapisname/rust-hsm",
  "entries": {
    "HSM Performance Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "distinct": true,
          "id": "d272765e7e21c382017dcdab81193df01fca2b0a",
          "message": "Fix YAML indentation error in benchmark workflow\n\n- Fix incorrect indentation of Store benchmark result step\n- YAML syntax is now correct",
          "timestamp": "2025-12-29T12:59:16-06:00",
          "tree_id": "dbb1eea1f97c8c41a57c63c73bbc200e80d80741",
          "url": "https://github.com/testingapisname/rust-hsm/commit/d272765e7e21c382017dcdab81193df01fca2b0a"
        },
        "date": 1767034898695,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 908.7652737088317,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 176.17432085424727,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11895.126852011776,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1027.4464017686544,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18171.37129526625,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8674.489436900723,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18524.412025900092,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28543.537457684204,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 344243.5592030073,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 292698.9181847984,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 295347.6832927723,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 32046.228607540095,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32783.015775187196,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 641362.7676086148,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27796.77223880763,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 407156.17696636077,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23917.780238651612,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115593.03852484789,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4722.045748879152,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9496.585977341145,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 373.73555730706306,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1355.0789170859732,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "distinct": true,
          "id": "fca99e4450d1ef5c41aaa2c883c4da425dbf7a2d",
          "message": "Simplify benchmark GitHub Pages path\n\n- Remove custom benchmark-data-dir-path to use default root path\n- Update benchmark results URL to point to root GitHub Pages",
          "timestamp": "2025-12-29T13:06:41-06:00",
          "tree_id": "89dcc25286748a79466ad1e194aab384facbda70",
          "url": "https://github.com/testingapisname/rust-hsm/commit/fca99e4450d1ef5c41aaa2c883c4da425dbf7a2d"
        },
        "date": 1767035339115,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 915.6773596904835,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 176.13717134538777,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11781.12738791671,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1028.3646414834975,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18029.17986703119,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8594.66707783554,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18425.286568482,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28611.66474682396,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 406705.7646475081,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 293913.63641707523,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 292981.9112967965,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31698.89599085043,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 33363.69429514191,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 642549.6369594551,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28471.615223203225,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 406639.61157784297,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23630.315994037595,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 108710.30443233653,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4844.680042311497,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9537.201571425629,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 390.72763010665483,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1353.000659154861,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "distinct": true,
          "id": "fa6a43c66e63a7e28f5f055fedda96743035ec77",
          "message": "refactor: Transform CLI to modular architecture\n\n- Refactor 842-line main.rs into clean 35-line entry point\n- Organize commands into focused modules by category:\n  * info.rs - Information and listing commands\n  * token.rs - Token management operations\n  * keys.rs - Key management operations\n  * crypto.rs - Sign/verify/encrypt/decrypt operations\n  * symmetric.rs - Symmetric key operations\n  * key_wrap.rs - Key wrapping/unwrapping\n  * mac.rs - HMAC and CMAC operations\n  * util.rs - Utility commands (benchmark, audit, troubleshooting)\n  * analyze.rs - Observability log analysis\n- Add commands/common.rs for shared utilities (PIN handling, config)\n- Implement commands/mod.rs as main dispatcher with routing logic\n- All 55 integration tests pass - no functionality lost\n- Update documentation with CLI_ARCHITECTURE.md\n- Improve maintainability, testability, and extensibility\n\nBreaking: None (full backward compatibility maintained)\nFeatures: Modular command architecture for easier maintenance",
          "timestamp": "2025-12-29T13:23:57-06:00",
          "tree_id": "507089a77ed7f005ba4122a5bb4426b9a8ace86f",
          "url": "https://github.com/testingapisname/rust-hsm/commit/fa6a43c66e63a7e28f5f055fedda96743035ec77"
        },
        "date": 1767036390850,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 901.2430322422758,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.94920726436567,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11584.379344866278,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1028.0935824239589,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18022.655198490713,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8129.163961009928,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18509.880574250536,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27601.83143671949,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 410047.8115748296,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 293829.0032732551,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 294053.6471473856,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31687.12387383962,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32877.60587904197,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 643045.4633142563,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28244.486535005937,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 410890.23478268017,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23168.32389687501,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 116165.06591205839,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4712.1001076243665,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9545.274573641222,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 380.97369516071285,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1326.8648847118945,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "fa6a43c66e63a7e28f5f055fedda96743035ec77",
          "message": "refactor: Transform CLI to modular architecture\n\n- Refactor 842-line main.rs into clean 35-line entry point\n- Organize commands into focused modules by category:\n  * info.rs - Information and listing commands\n  * token.rs - Token management operations\n  * keys.rs - Key management operations\n  * crypto.rs - Sign/verify/encrypt/decrypt operations\n  * symmetric.rs - Symmetric key operations\n  * key_wrap.rs - Key wrapping/unwrapping\n  * mac.rs - HMAC and CMAC operations\n  * util.rs - Utility commands (benchmark, audit, troubleshooting)\n  * analyze.rs - Observability log analysis\n- Add commands/common.rs for shared utilities (PIN handling, config)\n- Implement commands/mod.rs as main dispatcher with routing logic\n- All 55 integration tests pass - no functionality lost\n- Update documentation with CLI_ARCHITECTURE.md\n- Improve maintainability, testability, and extensibility\n\nBreaking: None (full backward compatibility maintained)\nFeatures: Modular command architecture for easier maintenance",
          "timestamp": "2025-12-29T19:23:57Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/fa6a43c66e63a7e28f5f055fedda96743035ec77"
        },
        "date": 1767036914680,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 917.5213454459607,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.94264314874667,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 12008.480869529298,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1026.480971331844,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18284.009171259,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8660.265575704145,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18395.953773175683,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28224.987016505973,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 406180.4415993761,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 298380.9847766021,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 269012.4552766793,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 32117.741069340915,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 33447.567926993324,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 567124.9035887663,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28560.787637977166,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 409711.80871375074,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23708.963932501527,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115298.76215248954,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4868.474746783326,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9670.987212440448,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 389.92856625644754,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1356.24666871912,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "distinct": true,
          "id": "2779bf3f6ab6c4ea8a58b12f8a0e5b4993229cce",
          "message": "Implement comprehensive PKCS#11 observability system\n\n- Add rust-hsm-analyze crate for parsing pkcs11-spy logs into structured JSON\n- Implement enhanced template parser with rich contextual data capture\n- Add analyze command to CLI with multiple output formats (text, JSON, events, pretty-events)\n- Add comprehensive observability documentation with real-world examples\n- Support complete session analysis with timing statistics and operation flow\n- Create 'Wireshark for PKCS#11' experience with detailed HSM operation visibility\n- Include performance monitoring, security auditing, and debugging capabilities\n- Add integration examples for Prometheus, ELK stack, and Grafana dashboards\n- Format code with cargo fmt for consistency",
          "timestamp": "2025-12-29T22:04:02-06:00",
          "tree_id": "0e33be77ea48098dc123f9c45d95e3ff8dda3fea",
          "url": "https://github.com/testingapisname/rust-hsm/commit/2779bf3f6ab6c4ea8a58b12f8a0e5b4993229cce"
        },
        "date": 1767067582581,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 1440.52955249258,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 191.06364239363967,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 15991.801962641872,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1079.3684908548237,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 24138.834992234537,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 10044.864382277001,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 24716.403980725157,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 45745.361191648364,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 465974.53915118077,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 311392.61003057874,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 309632.0332916362,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 53228.97615128953,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 49548.80854934962,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 857427.0329594952,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 44537.59730351571,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 460710.6000294855,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 30789.883675819474,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 77476.2574009195,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 6800.063050184601,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 11738.23822660575,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 591.4295074756039,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1089.2774879065146,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "distinct": true,
          "id": "7fd8aacb7998f4f28423040374fbe3d248bb6bf9",
          "message": "feat: Add Interactive TUI mode with scrollable command output\n\n- Implement complete TUI framework using ratatui 0.28 + crossterm 0.28\n- Add Interactive command to CLI with 6 menu categories\n- Implement real PKCS#11 command execution for info and list-slots\n- Add comprehensive scrolling system with PageUp/PageDown support\n- Fix scrolling logic consistency between render and scroll methods\n- Disable tracing for interactive mode to prevent TUI corruption\n- Add demo script and comprehensive documentation\n- Support both SoftHSM2 and Kryoptic HSM providers\n\nTUI Features:\n- Menu-driven interface with hierarchical navigation\n- Real-time status feedback with emojis and progress indicators\n- Scrollable command output for large results (tested with 146+ lines)\n- Graceful error handling and recovery\n- Clean terminal management and proper cleanup\n\nArchitecture:\n- crates/rust-hsm-cli/src/commands/interactive.rs (765 lines)\n- Modular command execution with real PKCS#11 integration\n- Consistent error handling and status management\n- Memory-safe PKCS#11 lifecycle (initialize/finalize)\n\nTested extensively in Docker with multiple HSM providers and various\noutput sizes. Foundation ready for expanding to full PKCS#11 functionality.",
          "timestamp": "2025-12-30T11:12:52-06:00",
          "tree_id": "a0239c0527a426c8e6d44de40a53bd2ebfa01c30",
          "url": "https://github.com/testingapisname/rust-hsm/commit/7fd8aacb7998f4f28423040374fbe3d248bb6bf9"
        },
        "date": 1767114961800,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 913.4995409208058,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.98600868994274,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11811.574208813512,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1018.6392442462825,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18176.0415053543,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8640.577881848738,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18676.040544936983,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28586.146353065207,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 405087.9040751843,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 292401.08071439434,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 289685.45952804445,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31821.453642188117,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32640.633802770928,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 640976.3351537061,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27979.400446215477,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 403645.72821725823,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23221.34915109714,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 112364.85317284636,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4687.092955271166,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9469.453059542406,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 382.5493386314887,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1330.2205463098724,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "7fd8aacb7998f4f28423040374fbe3d248bb6bf9",
          "message": "feat: Add Interactive TUI mode with scrollable command output\n\n- Implement complete TUI framework using ratatui 0.28 + crossterm 0.28\n- Add Interactive command to CLI with 6 menu categories\n- Implement real PKCS#11 command execution for info and list-slots\n- Add comprehensive scrolling system with PageUp/PageDown support\n- Fix scrolling logic consistency between render and scroll methods\n- Disable tracing for interactive mode to prevent TUI corruption\n- Add demo script and comprehensive documentation\n- Support both SoftHSM2 and Kryoptic HSM providers\n\nTUI Features:\n- Menu-driven interface with hierarchical navigation\n- Real-time status feedback with emojis and progress indicators\n- Scrollable command output for large results (tested with 146+ lines)\n- Graceful error handling and recovery\n- Clean terminal management and proper cleanup\n\nArchitecture:\n- crates/rust-hsm-cli/src/commands/interactive.rs (765 lines)\n- Modular command execution with real PKCS#11 integration\n- Consistent error handling and status management\n- Memory-safe PKCS#11 lifecycle (initialize/finalize)\n\nTested extensively in Docker with multiple HSM providers and various\noutput sizes. Foundation ready for expanding to full PKCS#11 functionality.",
          "timestamp": "2025-12-30T17:12:52Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/7fd8aacb7998f4f28423040374fbe3d248bb6bf9"
        },
        "date": 1767495118452,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 918.4761151296584,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.91676727551825,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11681.615240302506,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1025.9464104279327,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17943.01942977802,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8524.157975151056,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18257.64383645679,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28474.306778764316,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 397282.58710420725,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 287663.82454808016,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 269943.4198591975,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31236.91953994265,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32798.52065552436,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 613557.1589849311,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28232.3499817619,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 397061.7431010522,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23512.151079677977,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 114844.58082876443,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4808.810818593286,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9689.644560582372,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 391.927356233168,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1356.1921877308494,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "79948367cda75a3b7071137eab4478696416f162",
          "message": "fix: Remove double backslashes in cargo audit command\n\nGitHub Actions YAML doesn't need escaped backslashes for line continuation\nwhen using the | (literal) block scalar. Single backslashes work correctly\nfor shell line continuation.",
          "timestamp": "2026-01-09T05:51:14Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/79948367cda75a3b7071137eab4478696416f162"
        },
        "date": 1768099898990,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 890.1382632181214,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 172.9138856998477,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11724.407026390234,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1025.6032624029535,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17916.0033266435,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8638.417773579124,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18294.41866557583,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27633.637653373597,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 411671.71650638914,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 273044.99781564,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 295499.54197570996,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31406.522255289798,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32132.664202733973,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 644795.2130403384,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28123.36708699851,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 415855.74795814825,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23579.04426588296,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 116523.7696837778,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4762.025399881559,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9719.132617953337,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 384.56938124270994,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1351.039480318881,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "distinct": true,
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T09:54:40-06:00",
          "tree_id": "b9a877a3823921b76d2e5dccb44c2e091dc1b078",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1768147045642,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 900.5859230026774,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 170.56182108719923,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11633.320528925204,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1026.1980143478902,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18025.18912028425,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8570.650356376213,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18345.55391831679,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28584.806260758607,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 399064.5925949574,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 290733.17091040185,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 289383.6706582321,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31809.00347481554,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32875.76838889667,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 634461.4057126904,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28778.320025278877,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 409476.9341642986,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 24044.28765431624,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115493.71252229028,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4786.771355270915,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9569.009881150983,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 386.3482755074279,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1346.7383720454177,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1768704662648,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 899.0675482755219,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 173.74324646970229,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11606.211458673299,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1020.7284011777817,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17941.409814453527,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8650.602843210938,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18592.005140317582,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28511.440500615277,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 407767.14864743635,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 290643.6011904762,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 291441.52808622003,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31948.88178913738,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 33244.99031240983,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 634139.5360635155,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28784.416807566384,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 406507.36997861776,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23554.562495200757,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115865.45703129527,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4722.874477425746,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9469.099770790972,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 378.45179066129936,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1312.4847062719602,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1769309611806,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 896.9371336942381,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 173.9886211093817,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11481.311983297905,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1011.3149967091811,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17778.59322258692,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8565.131486759507,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18193.0581839471,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28415.58128618014,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 410549.47942326014,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 293083.23563892144,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 290998.8243647496,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31447.72758720455,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32826.16902194429,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 631640.1167270936,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28638.639366788226,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 410448.373803543,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23692.235959507125,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 109381.18687338252,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4725.1994128656215,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9602.402905303024,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 385.80372835630476,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1327.731157596218,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1769915235130,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 909.5810906095576,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.7440254245648,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11948.476258616645,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1028.4150248637843,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18332.10813743948,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8675.931404615942,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18410.015342906787,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28700.597661245698,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 404161.244169974,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 291728.9021657954,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 292650.9493596797,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31682.34520322957,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32120.36141830668,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 641469.7354578811,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28844.09593084801,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 409031.41361256543,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23966.435486429964,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 112705.51851300847,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4821.462218347052,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9559.957087264627,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 387.65923122305446,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1348.2106763617037,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1770520045854,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 898.5886299711585,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.05397097731898,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11621.528649392427,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1015.1101377242559,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18121.260224921083,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8505.265865255156,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18327.357392999387,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28723.432978752127,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 403222.5546568173,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 294103.80687967624,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 294000.04704000754,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31451.347595890442,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32874.44984608182,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 655119.1006524985,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28636.753096205743,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 407202.59958139574,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 21918.11567329383,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 111733.09198985463,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4378.535996207137,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9506.487797662392,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 375.2976279073238,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1325.4131942497745,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1771124823662,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 1422.1356552447369,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 190.83696102627965,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 15737.488617861356,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1069.3408743251791,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 23199.896806859004,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 10070.60501173729,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 24040.58820587975,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 44631.30082389382,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 471653.6175832469,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 313036.0742771997,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 312067.007027749,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 50128.93161210633,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 53479.424860873274,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 846568.0132741865,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 44337.99384765997,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 469920.3954850048,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 35582.30079426812,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 108524.37240355439,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 6753.123758691439,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 11927.475225441209,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 481.43820767565023,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1107.474190480112,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1771729547642,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 908.1075441978666,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.58976449194918,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11724.492253276232,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 997.4319319534382,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18068.198777650217,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8608.851000761711,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18731.776323109654,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28341.63459810712,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 405979.2625792675,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 294594.1964943291,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 270074.64863288216,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31621.17328466202,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32842.87966368892,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 569385.2916391464,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28153.29582188198,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 405847.45006047125,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23793.93311810928,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 112471.76958583396,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4812.963891508478,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9569.028194376053,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 392.0464778313124,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1355.7753195040455,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1772334449652,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 897.4269852956049,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.18327823474706,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 10953.79513949439,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1018.3459711086693,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 16856.226167403227,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8334.514056157956,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 16872.756134343585,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24769.212859184547,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 267741.9182101988,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 235166.85088069984,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 236370.85641888698,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 27233.768129519445,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 28569.534819406257,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 457950.94429484714,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24544.466965356467,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 301244.7432792298,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 20839.229098565804,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 103904.09236658196,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4428.50732909106,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9539.264950031422,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 353.8836318649647,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1333.8822169730695,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1772939053846,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 904.8305882975038,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.1717459997491,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11057.629045295367,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1025.0987431489832,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 16728.360861523965,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8323.797036528484,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 16758.81220242634,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24622.560766017716,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 303125.8335960424,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 234006.80491788703,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 235888.0003774208,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 27074.077383127977,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 28141.8393731349,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 473632.8587532089,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24490.01982712005,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 303622.82757866866,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 20513.9398375378,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 105889.57834769902,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4378.367676227766,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9615.811779330967,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 356.08004468605156,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1350.758696846362,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1773544064842,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 901.205898205153,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 172.4366023036702,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 10978.715125836936,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1013.9057169073849,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 16728.09781788655,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8344.427249361359,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 16761.300971954322,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24271.12595209559,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 304388.0582476988,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 234912.72992083442,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 222363.546609623,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 27208.84091426059,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 27968.663908956405,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 476444.57996645826,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 23743.212409152533,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 304610.58582707867,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 20809.255290857203,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 103282.73856246953,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4455.576256162842,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9698.510173058276,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 359.49850706021994,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1355.3820744811183,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1774148842478,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 901.1659735949357,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.45829337767833,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 10981.994580605315,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1020.4551666798203,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 16641.83150678138,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8288.274131020042,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 16841.986128266548,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24471.54913226334,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 278842.0248392476,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 232071.32944381787,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 232222.22738271614,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 22734.39272572183,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 27563.350225991908,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 464511.33407655143,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 24622.82752792721,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 297863.72139018954,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 20803.428405001145,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 105034.07305329849,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4407.119472337348,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9648.750737646993,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 354.7504479948295,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1353.7471911776404,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1774753724908,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 903.9417283004268,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 174.70325699666367,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11624.708830105577,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1018.0494258516833,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17620.207699960283,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8445.807560247746,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18049.92899157935,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27459.069510986923,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 407003.72001400095,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 267479.80527470174,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 293982.7608509037,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31436.457488478536,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32752.693581520143,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 635590.5271587833,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28307.922255122317,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 408266.5817472177,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 22336.974706950063,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115583.41886506329,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4596.789822633784,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9672.818837389083,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 386.33421227199744,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1333.9545292785276,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1775358490932,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 905.0933421858703,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 174.42090254514633,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11714.194276632103,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1027.7266889131126,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 18153.63713566104,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8639.35065258199,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18418.41782843907,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27978.44540565948,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 403574.0518027653,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 292961.3115291994,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 268138.20915852865,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31072.96180014368,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32456.42562577611,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 630286.5282557451,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27896.80414211748,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 402822.9834681447,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 22920.839214438663,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115378.84644229326,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4901.643619138369,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9601.905017955563,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 397.22810415530626,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1354.3379593816169,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "id": "07381028c296f9102bbe6cbbd2fbd746ea5448e9",
          "message": "feat: Refactor TUI into modular structure and fix display issues\n\n- Split TUI code into organized module structure (commands/tui/)\n  - app.rs: Core application state and event handling\n  - commands.rs: Command execution and HSM interaction\n  - menu.rs: Menu categories and navigation\n  - ui.rs: UI rendering and display formatting\n  - mod.rs: Module exports and entry point\n\n- Fix literal \\n characters showing in TUI command output\n- Update list-slots to display all slots with proper formatting\n- Add comprehensive TUI testing infrastructure (15 unit tests)\n- Create integration test framework for real HSM testing\n- Make TUI navigation methods public for testing access\n- Validate scrolling functionality with 18+ real HSM slots\n\nAll tests passing, TUI fully functional with real PKCS#11 data.\nModular architecture enables easier maintenance and testing.",
          "timestamp": "2026-01-11T15:54:40Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/07381028c296f9102bbe6cbbd2fbd746ea5448e9"
        },
        "date": 1775963319566,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 904.8964016686,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.22919023083108,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11811.342621300717,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1027.088451357882,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17996.91460895944,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8646.509922734787,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18398.241716835604,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 27873.367944623424,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 401081.31522584887,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 266368.33413243835,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 294122.83746183757,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31237.387904633502,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32544.540458070915,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 656064.6617330605,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28299.815032408947,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 389532.4831137668,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23319.90573161307,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115436.3841630516,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4653.831275905552,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9569.050170338662,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 390.9506405034262,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1346.7305731623371,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0321eeb35a71d6990b20647cd81cce7d5134c7af",
          "message": "Merge pull request #1 from testingapisname/copilot/fix-ci-cd-pipeline-issue\n\nfix: replace rand with HSM RNG to resolve RUSTSEC-2026-0097",
          "timestamp": "2026-04-12T07:29:59-05:00",
          "tree_id": "6fa64d7b2893c0c1c5f0fd0a2c460cab8969d002",
          "url": "https://github.com/testingapisname/rust-hsm/commit/0321eeb35a71d6990b20647cd81cce7d5134c7af"
        },
        "date": 1775997161397,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 842.6716094412591,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 157.41218993954263,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 12299.39078657556,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 935.4978358380165,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 16567.817544589794,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8138.820938777185,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 16564.140160453513,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 26135.05866536619,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 314691.03634052083,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 238309.71684039445,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 235198.93125605638,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 28926.898833956708,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 29859.03549343549,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 510641.77458229504,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 26338.149176116356,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 315107.5146840102,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 22158.13105914094,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 98644.03903936488,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4453.235725531406,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 12467.114867757571,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 347.59040494483776,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1231.5479328431002,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8cebe4c450cfd32081487edeb260c3980274a78b",
          "message": "Merge pull request #2 from testingapisname/copilot/fix-cargo-fmt-issues\n\nfix: apply cargo fmt to tui module",
          "timestamp": "2026-04-12T07:40:21-05:00",
          "tree_id": "f564ee34bbc9f677a2627b4dddaee41805c10cec",
          "url": "https://github.com/testingapisname/rust-hsm/commit/8cebe4c450cfd32081487edeb260c3980274a78b"
        },
        "date": 1775997788855,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 1428.8671632494452,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 191.1789409575271,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 15683.12066498941,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1064.118638842433,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 23604.61328562054,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 10073.055844820143,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 24124.742287440513,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 44524.82659806282,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 471693.66326732765,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 313081.15689749096,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 310231.43264875596,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 48093.06199868995,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 52850.826428372864,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 860155.8602418759,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 44382.26981579583,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 476303.8818766373,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 36126.61946603411,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 108761.14529836446,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 6651.6950314897895,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 11901.511658601807,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 465.0880795897417,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1059.645629917577,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "eilersjames15@gmail.com",
            "name": "James Eilers",
            "username": "testingapisname"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f4879c15c54663646d3d626be875cc424f81a4a3",
          "message": "Merge pull request #4 from testingapisname/copilot/fix-pipeline-error\n\nfix: collapse match arms to satisfy clippy collapsible_match in objects.rs",
          "timestamp": "2026-04-17T16:20:49-05:00",
          "tree_id": "eb12f1d9f35702f37ff35ab450831f8f88726567",
          "url": "https://github.com/testingapisname/rust-hsm/commit/f4879c15c54663646d3d626be875cc424f81a4a3"
        },
        "date": 1776461011614,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 1431.1500338123506,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 190.93906167626503,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 15698.779357109866,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1073.1638467068722,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 23450.03477640157,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 10118.464964106768,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 24102.820704901453,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 44625.04696786194,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 473758.5158093217,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 309187.8254201863,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 290525.38610823813,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 50033.92299979386,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 54368.923593176914,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 864677.9074794638,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 45232.740543190936,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 460948.4475256287,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 36369.37611244829,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 107131.99089806605,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 6736.628802321712,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 11787.890582913547,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 480.5075528243336,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1070.7128992787443,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f4879c15c54663646d3d626be875cc424f81a4a3",
          "message": "Merge pull request #4 from testingapisname/copilot/fix-pipeline-error\n\nfix: collapse match arms to satisfy clippy collapsible_match in objects.rs",
          "timestamp": "2026-04-17T21:20:49Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/f4879c15c54663646d3d626be875cc424f81a4a3"
        },
        "date": 1776568129001,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 896.4180033006111,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 174.53154807479518,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11149.430464792997,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1020.8491284214729,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 17942.665289626915,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 8603.122968049895,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18455.639471297607,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28440.0679603864,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 397981.4381457248,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 264322.3040446599,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 289549.5766785189,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 31367.884430676033,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 32653.5090440424,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 633809.9584220668,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28451.088595551842,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 399156.9804572742,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 23724.387151631097,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115447.3121556784,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4729.36090348954,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9396.93126295132,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 387.66567231713935,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1317.424327937058,
            "unit": "ops/sec"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "James Eilers",
            "username": "testingapisname",
            "email": "eilersjames15@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f4879c15c54663646d3d626be875cc424f81a4a3",
          "message": "Merge pull request #4 from testingapisname/copilot/fix-pipeline-error\n\nfix: collapse match arms to satisfy clippy collapsible_match in objects.rs",
          "timestamp": "2026-04-17T21:20:49Z",
          "url": "https://github.com/testingapisname/rust-hsm/commit/f4879c15c54663646d3d626be875cc424f81a4a3"
        },
        "date": 1777172965548,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "RSA-2048 Sign",
            "value": 900.9273118691245,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-4096 Sign",
            "value": 175.05337097195542,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-256 Sign",
            "value": 11840.785015628653,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P-384 Sign",
            "value": 1011.6990449480079,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Verify",
            "value": 16174.796496797875,
            "unit": "ops/sec"
          },
          {
            "name": "ECDSA-P256 Verify",
            "value": 6940.484512447621,
            "unit": "ops/sec"
          },
          {
            "name": "RSA-2048 Encrypt",
            "value": 18628.898190090767,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 28224.44530497642,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 393369.36596725596,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-384 Hash (1KB)",
            "value": 293932.6423956686,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-512 Hash (1KB)",
            "value": 295063.5862028267,
            "unit": "ops/sec"
          },
          {
            "name": "HMAC-SHA256",
            "value": 32652.890629795893,
            "unit": "ops/sec"
          },
          {
            "name": "AES-CMAC",
            "value": 33554.54727869266,
            "unit": "ops/sec"
          },
          {
            "name": "Random (32 bytes)",
            "value": 642384.5313804843,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1KB)",
            "value": 29271.31405368476,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1KB)",
            "value": 406210.1406299507,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (10KB)",
            "value": 24208.256855415217,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (10KB)",
            "value": 115253.31526161349,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (100KB)",
            "value": 4706.4590879748275,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (100KB)",
            "value": 9549.097352474562,
            "unit": "ops/sec"
          },
          {
            "name": "AES-256-GCM Encrypt (1MB)",
            "value": 393.793269906049,
            "unit": "ops/sec"
          },
          {
            "name": "SHA-256 Hash (1MB)",
            "value": 1346.867737857516,
            "unit": "ops/sec"
          }
        ]
      }
    ]
  }
}