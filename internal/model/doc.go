// Package model holds the small shared vocabulary every other package uses:
// identifiers, the render context, holds, and the status record a machine
// publishes. It has no behaviour and imports nothing from this module.
//
// Exported types other packages use:
//
//   - MachineID, TypeName, EnclaveName, Scope, Target, SourcePath, CommitID, Epoch
//   - Machine: one registry entry (declared facts included)
//   - ObservedFact: one collector's normalized output on one machine
//   - Context: everything a render or a rule may read for one machine
//   - Hold, HoldReason: a file the tool refuses to move in either direction
//   - Status, TaskResult: the record published in a machine's status ref
//   - ErrNotImplemented: the sentinel every stub returns
//
// Import direction for the module: model is at the bottom; cli is at the top.
//
//	model <- cond, extexec, crypt, schedule
//	      <- fleet (cond, extexec), manifest (cond), render (cond)
//	      <- rules (manifest), store (fleet), tasks (manifest, extexec)
//	      <- apply <- sync <- importer <- cli
//
// secrecytest and fixture are test helpers; no production package imports them.
package model
