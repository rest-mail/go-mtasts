# Coverage exceptions

CI measures statement coverage across `./...` with `-coverpkg=./...` and fails
when the total falls below 95%. Tests in the public package also cover the
internal domain-name, policy grammar, cache and TXT-record packages. These are the
statements left uncovered on purpose, each with the reason. Add an entry here
whenever you leave a statement uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover; CI also runs the command itself. |
