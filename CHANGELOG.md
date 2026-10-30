# Changelog

## [0.22.2](https://github.com/compliance-framework/api/compare/v0.22.1...v0.22.2) (2026-10-30)


### Bug Fixes

* **deps:** build with the go1.26.10 toolchain so Renovate can ship Go security fixes ([#538](https://github.com/compliance-framework/api/issues/538)) ([202d01e](https://github.com/compliance-framework/api/commit/202d01e25ab59ac13cf81645ddede18a7d234fe3))
* **deps:** update aws-sdk-go-v2 monorepo ([#544](https://github.com/compliance-framework/api/issues/544)) ([5cc55a6](https://github.com/compliance-framework/api/commit/5cc55a606c9223e7e7dad4d39f0f4f1fe2170647))

## [0.22.1](https://github.com/compliance-framework/api/compare/v0.22.0...v0.22.1) (2026-10-28)


### Bug Fixes

* **config:** bind CCF_EVIDENCE_BATCH_*, CCF_SSP_SCOPE_* and CCF_SSP_TEMPLATE_* env vars ([#535](https://github.com/compliance-framework/api/issues/535)) ([a6d950e](https://github.com/compliance-framework/api/commit/a6d950e858c1588818babe68d29136116eb225df))

## [0.22.0](https://github.com/compliance-framework/api/compare/v0.21.1...v0.22.0) (2026-10-28)


### Features

* **api:** POST /evidence/batches and GET /evidence/batches/{id} ([#505](https://github.com/compliance-framework/api/issues/505)) ([61ddb2c](https://github.com/compliance-framework/api/commit/61ddb2c95389f29317e1834313e7e3980d7ba6f4))
* **evidence:** batch service for asynchronous evidence ingest ([#504](https://github.com/compliance-framework/api/issues/504)) ([d1cb975](https://github.com/compliance-framework/api/commit/d1cb975dbf867f1fc2cd9ad21d8baa314f575eec))
* **evidence:** prune evidence batches after a retention period ([#509](https://github.com/compliance-framework/api/issues/509)) ([10d9c53](https://github.com/compliance-framework/api/commit/10d9c538de06ecaf653696c4681f2972283b1a66))
* **sdk:** CreateBatch, GetBatch and WaitForBatch for evidence batches ([#506](https://github.com/compliance-framework/api/issues/506)) ([c0a622a](https://github.com/compliance-framework/api/commit/c0a622aaaeba7bf905a20eafa6d0fe153ac264b6))
* **ssp-scope:** automatic per-policy filters ([#520](https://github.com/compliance-framework/api/issues/520)) ([81b157d](https://github.com/compliance-framework/api/commit/81b157d384f357f7b52ce77d51c56d07a6bfba41))
* **ssp-scope:** filters that follow the SSP scope ([#519](https://github.com/compliance-framework/api/issues/519)) ([9dba7b1](https://github.com/compliance-framework/api/commit/9dba7b1c6ccbe1947d8af0fef4d53409715a0990))
* **ssp-scope:** restrict filter-building inputs to the SSP scope ([#518](https://github.com/compliance-framework/api/issues/518)) ([6feac53](https://github.com/compliance-framework/api/commit/6feac5331ab620e10c40079154cb6af12e977245))
* **ssp-scope:** scope models and sspscope service ([#516](https://github.com/compliance-framework/api/issues/516)) ([bb0c476](https://github.com/compliance-framework/api/commit/bb0c476d54aefd1563dcdc7ff412dedb34766422))
* **ssp-scope:** scope routes and SSP-scoped evidence search ([#517](https://github.com/compliance-framework/api/issues/517)) ([0ad30ed](https://github.com/compliance-framework/api/commit/0ad30ed9efd277bb99f46face92cde71f4aab3e7))
* **ssp-templates:** discovery planner and preview route ([#524](https://github.com/compliance-framework/api/issues/524)) ([9a875e3](https://github.com/compliance-framework/api/commit/9a875e304a5daa6cd41111afa4b51696eac56825))
* **ssp-templates:** discovery worker and periodic job ([#525](https://github.com/compliance-framework/api/issues/525)) ([c7856f1](https://github.com/compliance-framework/api/commit/c7856f17689e11e2d39b8db478c43e5ab156be66))
* **ssp-templates:** run, created SSPs and forget routes ([#526](https://github.com/compliance-framework/api/issues/526)) ([75918b2](https://github.com/compliance-framework/api/commit/75918b271a5d9ffa40156c930864362efd09bb2f))
* **ssp-templates:** SSP template model and admin CRUD routes ([#522](https://github.com/compliance-framework/api/issues/522)) ([b647d23](https://github.com/compliance-framework/api/commit/b647d23c010209581b8af2ffcd6aa3398cd067b2))
* **worker:** evidence batch chunk queue and worker ([#503](https://github.com/compliance-framework/api/issues/503)) ([7a2be54](https://github.com/compliance-framework/api/commit/7a2be54d3ab11267eb3b9c557446be8079918d3f))


### Bug Fixes

* **deps:** update all non-major dependencies ([#531](https://github.com/compliance-framework/api/issues/531)) ([e7fa71c](https://github.com/compliance-framework/api/commit/e7fa71c5a12d8c724293f5ca276088ed77c86e50))
* **deps:** update aws-sdk-go-v2 monorepo ([#532](https://github.com/compliance-framework/api/issues/532)) ([2f0c91e](https://github.com/compliance-framework/api/commit/2f0c91ee83d5384d9cd001404fc632b5c7e26373))
* **deps:** update module github.com/go-jose/go-jose/v3 to v4 [security] ([#530](https://github.com/compliance-framework/api/issues/530)) ([95c08b2](https://github.com/compliance-framework/api/commit/95c08b22fa998bee2341116004cbf6377def691b))
* **deps:** update module github.com/open-policy-agent/opa to v1.21.3 ([#533](https://github.com/compliance-framework/api/issues/533)) ([e49cede](https://github.com/compliance-framework/api/commit/e49cede6930b3104c5024836627a5bb1f2eaea53))
* **deps:** update river monorepo to v0.49.0 ([#534](https://github.com/compliance-framework/api/issues/534)) ([0d12d7c](https://github.com/compliance-framework/api/commit/0d12d7c951bb6e96cbf4298534493bb89348d769))
* **deps:** update security fixes (gomod) [security] ([#529](https://github.com/compliance-framework/api/issues/529)) ([dea901c](https://github.com/compliance-framework/api/commit/dea901c2310591e753a10b69f9913ac5cdcb8c4c))


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
