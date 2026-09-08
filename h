[1mdiff --git a/Cargo.lock b/Cargo.lock[m
[1mindex d2c3a3a..1051104 100644[m
[1m--- a/Cargo.lock[m
[1m+++ b/Cargo.lock[m
[36m@@ -58,12 +58,39 @@[m [mversion = "1.0.14"[m
 source = "registry+https://github.com/rust-lang/crates.io-index"[m
 checksum = "940b3a0ca603d1eade50a4846a2afffd5ef57a9feac2c0e2ec2e14f9ead76000"[m
 [m
[32m+[m[32m[[package]][m
[32m+[m[32mname = "argon2"[m
[32m+[m[32mversion = "0.5.3"[m
[32m+[m[32msource = "registry+https://github.com/rust-lang/crates.io-index"[m
[32m+[m[32mchecksum = "3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072"[m
[32m+[m[32mdependencies = [[m
[32m+[m[32m "base64ct",[m
[32m+[m[32m "blake2",[m
[32m+[m[32m "cpufeatures",[m
[32m+[m[32m "password-hash",[m
[32m+[m[32m][m
[32m+[m
 [[package]][m
 name = "autocfg"[m
 version = "1.5.1"[m
 source = "registry+https://github.com/rust-lang/crates.io-index"[m
 checksum = "f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53"[m
 [m
[32m+[m[32m[[package]][m
[32m+[m[32mname = "base64ct"[m
[32m+[m[32mversion = "1.8.3"[m
[32m+[m[32msource = "registry+https://github.com/rust-lang/crates.io-index"[m
[32m+[m[32mchecksum = "2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06"[m
[32m+[m
[32m+[m[32m[[package]][m
[32m+[m[32mname = "blake2"[m
[32m+[m[32mversion = "0.10.6"[m
[32m+[m[32msource = "registry+https://github.com/rust-lang/crates.io-index"[m
[32m+[m[32mchecksum = "46502ad458c9a52b69d4d4d32775c788b7a1b85e8bc9d482d92250fc0e3f8efe"[m
[32m+[m[32mdependencies = [[m
[32m+[m[32m "digest",[m
[32m+[m[32m][m
[32m+[m
 [[package]][m
 name = "block-buffer"[m
 version = "0.10.4"[m
[36m@@ -350,6 +377,15 @@[m [mversion = "0.5.2"[m
 source = "registry+https://github.com/rust-lang/crates.io-index"[m
 checksum = "fc0fef456e4baa96da950455cd02c081ca953b141298e41db3fc7e36b1da849c"[m
 [m
[32m+[m[32m[[package]][m
[32m+[m[32mname = "hkdf"[m
[32m+[m[32mversion = "0.12.4"[m
[32m+[m[32msource = "registry+https://github.com/rust-lang/crates.io-index"[m
[32m+[m[32mchecksum = "7b5f8eb2ad728638ea2c7d47a21db23b7b58a72ed6a38256b8a1849f15fbbdf7"[m
[32m+[m[32mdependencies = [[m
[32m+[m[32m "hmac",[m
[32m+[m[32m][m
[32m+[m
 [[package]][m
 name = "hmac"[m
 version = "0.12.1"[m
[36m@@ -428,11 +464,13 @@[m [mchecksum = "cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98"[m
 [m
 [[package]][m
 name = "mrs_auth_pqc"[m
[31m-version = "0.3.1"[m
[32m+[m[32mversion = "0.4.0"[m
 dependencies = [[m
  "aes-gcm",[m
[32m+[m[32m "argon2",[m
  "criterion",[m
  "crypto-bigint",[m
[32m+[m[32m "hkdf",[m
  "hmac",[m
  "pqc_kyber",[m
  "rand",[m
[36m@@ -468,6 +506,17 @@[m [mversion = "0.3.1"[m
 source = "registry+https://github.com/rust-lang/crates.io-index"[m
 checksum = "c08d65885ee38876c4f86fa503fb49d7b507c2b62552df7c70b2fce627e06381"[m
 [m
[32m+[m[32m[[package]][m
[32m+[m[32mname = "password-hash"[m
[32m+[m[32mversion = "0.5.0"[m
[32m+[m[32msource = "registry+https://github.com/rust-lang/crates.io-index"[m
[32m+[m[32mchecksum = "346f04948ba92c43e8469c1ee6736c7563d71012b17d40745260fe106aac2166"[m
[32m+[m[32mdependencies = [[m
[32m+[m[32m "base64ct",[m
[32m+[m[32m "rand_core",[m
[32m+[m[32m "subtle",[m
[32m+[m[32m][m
[32m+[m
 [[package]][m
 name = "pin-project-lite"[m
 version = "0.2.17"[m
