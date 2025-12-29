window.BENCHMARK_DATA = {
  "lastUpdate": 1767036914897,
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
      }
    ]
  }
}