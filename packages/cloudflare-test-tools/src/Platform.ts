// Single import boundary for @effect/platform-* (mirrors the other packages'
// Platform.ts). No lazy loading here: @effect/platform-node is a hard
// dependency of this package, so it can never be missing at runtime.
export * as NodeRuntime from "@effect/platform-node/NodeRuntime";
export * as NodeServices from "@effect/platform-node/NodeServices";
