# Certificate deployment recovery

`run` and both `renew` modes prepare certificate exports before publishing them.
A durable journal records the local certificate files, DSM archive, assigned
services and successful service reloads. Each file is replaced atomically, using
a temporary file in its destination directory followed by file and directory
synchronization. Existing service file ownership and permissions are preserved;
new files are private (`0600`). Unsupported symlinks and non-regular destination
files are rejected instead of being replaced implicitly.

Synolego takes a non-blocking lock on the shared DSM archive and the selected
`--path` data directory. Another invocation exits with an error while the lock is
held. These locks coordinate Synolego only, not DSM or other certificate tools.

## After an interrupted deployment

Rerun `run` or `renew` with the same `--path`. Recovery occurs before account setup
or any ACME request. If a deployment was pending, that invocation completes the
pending deployment and exits without requesting another certificate or running a
user hook. Invoke the intended command again afterwards if other work is needed.
The target DSM ID and export contents come from the journal, not from newly
supplied export flags or a newly selected default certificate.

A service whose reload failed is retried even when its files already match.
Completed services are not reloaded again. If the process stopped after a reload
succeeded but before its checkpoint was saved, that reload may run again: DSM
reload scripts must tolerate repeated execution. User hooks are not replayed,
because their effects may not be idempotent.

An unfinished deployment blocks other `--path` data stores from changing the
same DSM archive. Resume the owning store first; the error identifies its path.
Lock files are retained intentionally and are not stale process markers.

## Conflicts and damaged state

The journal is under `<path>/.synolego-transactions/`. Its generation files
contain private keys: directories use `0700` and staged files use `0600`.
Do not publish or log their contents. Completed generations are deleted;
preparation interrupted before journal publication can leave unreferenced
generation directories. Retain them for manual inspection and remove them only
after confirming that no pending journal references them.

Recovery accepts only the recorded old or new contents and metadata. Changes to
the DSM index, default selection, staged contents or unrelated destination
contents stop recovery with an error. A global deployment marker without its
journal also requires manual recovery; it can result from an interruption during
preparation or removal/loss of the data store. Do not delete the marker or journal
to bypass the error: back up the state and establish which key/certificate pair
and service assignments should be restored first.

This is forward recovery, not automatic rollback. Keep independent backups of
the data store and DSM certificate configuration. Several files or services may
temporarily hold different generations until recovery completes; individual
atomic writes do not provide a simultaneous multi-file switch. Power-loss
durability depends on the underlying filesystem honoring synchronization.

Test owners, modes, filesystem synchronization, service paths and reload scripts
on the supported DSM version before production use. No compatibility with
uncoordinated DSM configuration changes during deployment is guaranteed.
