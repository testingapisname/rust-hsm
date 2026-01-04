window.BENCHMARK_DATA = {
  "lastUpdate": 1767495119047,
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
      }
    ]
  }
}