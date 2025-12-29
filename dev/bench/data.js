window.BENCHMARK_DATA = {
  "lastUpdate": 1767034899296,
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
      }
    ]
  }
}