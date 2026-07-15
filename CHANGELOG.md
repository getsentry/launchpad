# Changelog## 26.5.1

### Bug Fixes 🐛

- (android) Add missing Android binary chunk types and improve parsing robustness by @sentry in [#626](https://github.com/getsentry/launchpad/pull/626)

### Internal Changes 🔧

- (security) Add SafeDirectory to enforce path traversal checks by @runningcode in [#623](https://github.com/getsentry/launchpad/pull/623)

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

