# Changelog## 26.5.1

### Bug Fixes 🐛

- (android) Add missing Android binary chunk types and improve parsing robustness by @sentry in [#626](https://github.com/getsentry/launchpad/pull/626)

### Internal Changes 🔧

- (security) Add SafeDirectory to enforce path traversal checks by @runningcode in [#623](https://github.com/getsentry/launchpad/pull/623)

## 26.9.0

### New Features ✨

#### Size

- Store app icons in preprod_size by @NicoHinderling in [#684](https://github.com/getsentry/launchpad/pull/684)
- Add Apple binary analysis telemetry by @jamieQ in [#682](https://github.com/getsentry/launchpad/pull/682)
- Log the binary analysis pool size at INFO by @NicoHinderling in [#673](https://github.com/getsentry/launchpad/pull/673)
- Drive binary analysis worker count from sentry-options by @NicoHinderling in [#672](https://github.com/getsentry/launchpad/pull/672)
- Log per-insight timing in Apple analyzer by @NicoHinderling in [#665](https://github.com/getsentry/launchpad/pull/665)

#### Worker

- Tag processing duration with platform (ios/android/timeout/failed) by @NicoHinderling in [#667](https://github.com/getsentry/launchpad/pull/667)
- Tag processing duration metric with organization_slug by @NicoHinderling in [#666](https://github.com/getsentry/launchpad/pull/666)

#### Other

- (logging) Stamp the artifact id onto every log record by @NicoHinderling in [#670](https://github.com/getsentry/launchpad/pull/670)
- (options) Wire up sentry-options for dynamic config by @NicoHinderling in [#668](https://github.com/getsentry/launchpad/pull/668)

### Bug Fixes 🐛

- (size) Keep demangle parallelism inside binary analysis workers by @NicoHinderling in [#671](https://github.com/getsentry/launchpad/pull/671)

### Internal Changes 🔧

#### Size

- Reduce overlapping LIEF object lifetimes by @jamieQ in [#680](https://github.com/getsentry/launchpad/pull/680)
- Reduce Apple symbol analysis memory by @jamieQ in [#679](https://github.com/getsentry/launchpad/pull/679)
- Add compact Swift demangling rollout by @jamieQ in [#677](https://github.com/getsentry/launchpad/pull/677)
- Remove per-binary full GC by @jamieQ in [#676](https://github.com/getsentry/launchpad/pull/676)
- Parallelize Apple binary analysis across processes by @NicoHinderling in [#663](https://github.com/getsentry/launchpad/pull/663)
- Dedupe images in ImageOptimization insight by @NicoHinderling in [#664](https://github.com/getsentry/launchpad/pull/664)

#### Other

- (android) Target bundletool builds to device by @jamieQ in [#658](https://github.com/getsentry/launchpad/pull/658)
- (claude) Disable co-author attribution by @sentry-junior in [#647](https://github.com/getsentry/launchpad/pull/647)
- (options) Validate sentry-options schema changes on PRs by @NicoHinderling in [#669](https://github.com/getsentry/launchpad/pull/669)
- Remove unused MinIO E2E scaffolding by @jamieQ in [#681](https://github.com/getsentry/launchpad/pull/681)

## 26.8.0

### Bug Fixes 🐛

- (deps) Bump Pillow to 12.3.0 by @jamieQ in [#650](https://github.com/getsentry/launchpad/pull/650)
- (preprod) Accept CFBundleVersion groups beyond the third by @trevor-e in [#657](https://github.com/getsentry/launchpad/pull/657)
- Clean up bundletool temporary files by @jamieQ in [#655](https://github.com/getsentry/launchpad/pull/655)

### Internal Changes 🔧

- (android) Cache DEX lookup tables by @jamieQ in [#656](https://github.com/getsentry/launchpad/pull/656)
- Record and collect some DEX processing stats by @jamieQ in [#654](https://github.com/getsentry/launchpad/pull/654)
- Fix Android AAB cleanup and mapping cache by @jamieQ in [#653](https://github.com/getsentry/launchpad/pull/653)
- Add more spans to investigate long processing times by @jamieQ in [#652](https://github.com/getsentry/launchpad/pull/652)
- Replace curl-pipe-bash with action-setup-cli for Sentry CLI setup by @oioki in [#651](https://github.com/getsentry/launchpad/pull/651)

## 26.7.2

### Internal Changes 🔧

- (gocd) Bump gocd-jsonnet to 3.0.7 by @dmajere in [#648](https://github.com/getsentry/launchpad/pull/648)

## 26.7.0

### Bug Fixes 🐛

#### Taskworker

- Cleanup unused arg by @evanh in [#644](https://github.com/getsentry/launchpad/pull/644)
- Remove erroneous arg by @evanh in [#643](https://github.com/getsentry/launchpad/pull/643)

#### Other

- (preprod) Parse dotted Apple build numbers instead of dropping them by @trevor-e in [#645](https://github.com/getsentry/launchpad/pull/645)
- Support push-based workers in launchpad by @evanh in [#639](https://github.com/getsentry/launchpad/pull/639)

### Internal Changes 🔧

- (deps) Bump taskbroker-client to 0.20.0 by @untitaker in [#634](https://github.com/getsentry/launchpad/pull/634)
- (gocd) Deploy image from multi-region registry by @chromy in [#646](https://github.com/getsentry/launchpad/pull/646)
- Remove unused HEALTHCHECK_MAX_AGE_SECONDS constant by @NicoHinderling in [#638](https://github.com/getsentry/launchpad/pull/638)

### Other

- chore(tasks) Remove metrics prefix from taskworker runtime by @markstory in [#637](https://github.com/getsentry/launchpad/pull/637)
- chore(tasks) Switch to taskbroker-client metrics by @markstory in [#635](https://github.com/getsentry/launchpad/pull/635)

## 26.6.0

### Bug Fixes 🐛

- (size) Skip empty image files and demote UnidentifiedImageError logging by @sentry in [#629](https://github.com/getsentry/launchpad/pull/629)

### Internal Changes 🔧

- Brew-managed uv, requirements -> uv.lock, pin 3.14.4-slim-bookworm by @kenzoengineer in [#631](https://github.com/getsentry/launchpad/pull/631)

## 26.5.2

### Internal Changes 🔧

- (gocd) Gocd-jsonnet 3.0.4 by @dmajere in [#628](https://github.com/getsentry/launchpad/pull/628)

