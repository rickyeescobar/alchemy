// Single import boundary for @effect/platform-* (mirrors the other packages'
// Platform.ts). No lazy loading here: @effect/platform-bun is a hard
// dependency of this package, so it can never be missing at runtime.
export * as BunRuntime from "@effect/platform-bun/BunRuntime";
export * as BunServices from "@effect/platform-bun/BunServices";
