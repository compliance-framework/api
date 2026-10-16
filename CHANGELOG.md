# Changelog

## [0.22.0](https://github.com/compliance-framework/api/compare/v0.21.1...v0.22.0) (2026-10-16)


### Features

* **api:** POST /evidence/batches and GET /evidence/batches/{id} ([#505](https://github.com/compliance-framework/api/issues/505)) ([61ddb2c](https://github.com/compliance-framework/api/commit/61ddb2c95389f29317e1834313e7e3980d7ba6f4))
* **evidence:** batch service for asynchronous evidence ingest ([#504](https://github.com/compliance-framework/api/issues/504)) ([d1cb975](https://github.com/compliance-framework/api/commit/d1cb975dbf867f1fc2cd9ad21d8baa314f575eec))
* **evidence:** prune evidence batches after a retention period ([#509](https://github.com/compliance-framework/api/issues/509)) ([10d9c53](https://github.com/compliance-framework/api/commit/10d9c538de06ecaf653696c4681f2972283b1a66))
* **sdk:** CreateBatch, GetBatch and WaitForBatch for evidence batches ([#506](https://github.com/compliance-framework/api/issues/506)) ([c0a622a](https://github.com/compliance-framework/api/commit/c0a622aaaeba7bf905a20eafa6d0fe153ac264b6))
* **worker:** evidence batch chunk queue and worker ([#503](https://github.com/compliance-framework/api/issues/503)) ([7a2be54](https://github.com/compliance-framework/api/commit/7a2be54d3ab11267eb3b9c557446be8079918d3f))


### Performance Improvements

* **compliance:** batch profile compliance and leverage posture evidence counts ([#502](https://github.com/compliance-framework/api/issues/502)) ([673416e](https://github.com/compliance-framework/api/commit/673416e77a87a16bec7f6da46fb87e45117de974))
* **evidence:** latest evidence per stream via skip scan, not DISTINCT ON ([#511](https://github.com/compliance-framework/api/issues/511)) ([b484ffa](https://github.com/compliance-framework/api/commit/b484ffa6298c3ed73d74bd56131878aaab95232f))
* **evidence:** match filter sets to evidence through the label index ([#514](https://github.com/compliance-framework/api/issues/514)) ([ee0a710](https://github.com/compliance-framework/api/commit/ee0a710ff5f7cc4168fcb27cab8b9d0bceba3b32))
* **evidence:** store evidence in 36 SQL statements instead of 65 ([#510](https://github.com/compliance-framework/api/issues/510)) ([82bf122](https://github.com/compliance-framework/api/commit/82bf1222aa46956ee52dcc70d877f5e9f0d1cf2b))
* **lineage:** label index and shared engine cache for the Compliance Map ([#513](https://github.com/compliance-framework/api/issues/513)) ([364388a](https://github.com/compliance-framework/api/commit/364388a8c0aff12cdd7bd2d52fe550cf46fb4c6d))

## [0.21.1](https://github.com/compliance-framework/api/compare/v0.21.0...v0.21.1) (2026-10-14)


### Bug Fixes

* **deps:** update module github.com/moby/go-archive to v0.3.0 [security] ([#492](https://github.com/compliance-framework/api/issues/492)) ([e71ddf2](https://github.com/compliance-framework/api/commit/e71ddf2faf2fad17c397cc56fa6156a2a86267a6))
* **deps:** update module golang.org/x/crypto to v0.56.0 [security] ([#494](https://github.com/compliance-framework/api/issues/494)) ([9b8abe7](https://github.com/compliance-framework/api/commit/9b8abe7ee2c0927eefc5f0af2ae5bf823831cb1c))
* **deps:** update module golang.org/x/mod to v0.40.0 [security] ([#495](https://github.com/compliance-framework/api/issues/495)) ([f968a6b](https://github.com/compliance-framework/api/commit/f968a6b7adb408852248f16efe51507a87ac0bf3))
* **deps:** update module golang.org/x/net to v0.60.0 [security] ([#501](https://github.com/compliance-framework/api/issues/501)) ([bdd97c6](https://github.com/compliance-framework/api/commit/bdd97c686043c34de6523eb4a515306cb52e48c9))
* **worker:** lock the risk while resolving its evidence links ([#490](https://github.com/compliance-framework/api/issues/490)) ([b9958ae](https://github.com/compliance-framework/api/commit/b9958ae80150cb0a1f7e856641a36119f8119360))
