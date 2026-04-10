// Package risk implements the SentinelCore risk correlation engine.
//
// The risk package groups related findings into persistent, explainable
// "risk clusters" that survive across scan re-runs. It subscribes to
// scan completion events, debounces per project, and rebuilds the cluster
// view in a single database transaction guarded by an advisory lock.
//
// See docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md
// for the full design rationale.
package risk
