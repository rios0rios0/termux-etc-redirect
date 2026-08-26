---
name: code-review
description: "Review pull requests and diffs in termux-etc-redirect — the LD_PRELOAD and seccomp `/etc` redirection layer for Termux — against the rios0rios0/guide standards, with extra weight on the three tiers sharing one redirect table, the race-free ptrace model, and the reentrancy guards. Use when reviewing a PR, a branch, or staged changes here."
---

# Code review — `termux-etc-redirect`

`termux-etc-redirect` makes Go CLIs resolve DNS and verify TLS under Termux without `proot`, using an `LD_PRELOAD` shim (tier 1), a hybrid seccomp `user_notif` + ptrace supervisor (tier 2), and a narrow seccomp supervisor for musl binaries (tier 3). It manipulates syscalls and process tracing, so ordering and reentrancy are the whole game.

## When to use this skill

Use it whenever you are asked to review a pull request, a diff, a branch, or staged changes
in this repository — and before opening a pull request of your own, as a self-check. It is a
**review** skill: it produces findings, not commits.

## Source of truth

The canonical engineering standards live in the
**[rios0rios0/guide wiki](https://github.com/rios0rios0/guide/wiki)**. This file is a
repo-tailored index into that guide plus the rules that only apply here. Precedence, highest
first:

1. This repository's `.github/copilot-instructions.md`, `CLAUDE.md`, and `CONTRIBUTING.md` —
   they describe *this* codebase and its load-bearing invariants.
2. The **rios0rios0/guide** wiki — the shared standard.
3. General language idiom.

When the guide and a general convention disagree, the guide wins. When this file and the
guide disagree, the guide wins and this file should be corrected in the same pull request.

### Guide pages that apply here

| Topic | Page |
|-------|------|
| Mapper Design Pattern — replacing `switch`/`case` | [Mapper-Design-Pattern](https://github.com/rios0rios0/guide/wiki/Mapper-Design-Pattern) |
| Git Flow — branches, commits, SemVer, breaking changes | [Git-Flow](https://github.com/rios0rios0/guide/wiki/Git-Flow) |
| Documentation & Change Control — changelog and docs discipline | [Documentation-&-Change-Control](https://github.com/rios0rios0/guide/wiki/Documentation-&-Change-Control) |
| CHANGELOG Formatting — capitalisation and backticks | [CHANGELOG-Formatting](https://github.com/rios0rios0/guide/wiki/CHANGELOG-Formatting) |
| Security — OWASP checklist, secret hygiene, SAST | [Security](https://github.com/rios0rios0/guide/wiki/Security) |
| CI & CD — pipeline stages and the local quality gates | [CI-&-CD](https://github.com/rios0rios0/guide/wiki/CI-&-CD) |
| Code Style — baseline naming and the operations vocabulary | [Code-Style](https://github.com/rios0rios0/guide/wiki/Code-Style) |

## How to run the review

1. **Establish the range.** Resolve the default branch with
   `git symbolic-ref refs/remotes/origin/HEAD` (strip `refs/remotes/origin/`; fall back to `main`),
   then read the diff with `git diff <default>...HEAD` and the file list with
   `git diff <default>...HEAD --name-only`.
2. **Read whole files, not just hunks.** A hunk cannot show a layering violation, a missing
   test, or a duplicated helper. Open every changed file in full, plus the files it imports
   from the layer below.
3. **Check the change set as a unit** — not only the code. A change that alters behaviour,
   configuration, or architecture is incomplete without its changelog entry and its
   documentation update, and that omission is a finding in its own right.
4. **Map every finding to a rule.** Each finding must name the rule it breaks and link the
   guide page (or the repository file) that states it. A comment that cannot be traced to a
   rule is a suggestion, not a defect — label it as such.
5. **Report, do not rewrite.** Produce the review in the output format below. Only edit files
   when the request explicitly asks for fixes.

## What matters most in `termux-etc-redirect`

These are the checks that catch real defects in this repository. Work through
them before the generic ones.

- **`REDIRECT_TABLE` is duplicated across the three tiers on purpose.** A path added to one tier and not the others produces behaviour that depends on which wrapper the user happened to run. Change all three together. **Critical.**
- **The tier-2 ptrace model is race-free by construction and must stay that way.** The child calls `ptrace(PTRACE_TRACEME)` and `raise(SIGSTOP)` *before* `execvp`, so `PTRACE_O_TRACECLONE|TRACEFORK|TRACEVFORK` is installed before any Go runtime thread is cloned; the parent's main thread runs a blocking `waitpid(-1, __WALL)` loop with every ptrace operation on that one OS thread, while a dedicated pthread polls `notif_fd`. The earlier `PTRACE_SEIZE` + `poll` + `SIGCHLD` design raced with Go's rapid `clone()`. Reintroducing it is a Critical finding.
- **The notif thread is spawned before the ack is written to the child**, so the child's first `execvp`-triggered `openat` always has a consumer. Reordering those two steps deadlocks the first call.
- **The reentrancy guard runs before `build_prefix()`.** `TERMUX_ETC_WRAP_ACTIVE` plus `/proc/self/status:TracerPid` short-circuits to `execvp` when already wrapped, and it must stay independent of `PREFIX` validation — otherwise nesting breaks in environments where `PREFIX` is unusual.
- **Tier 2 rewrites the `SIGSYS` from Android's `faccessat2` trap to `-ENOSYS`** so Go's runtime falls back. Tier 3 deliberately does *not* do that, which is what makes it compose with `strace`, `gdb`, and nested wrappers. Do not "unify" the two.
- **`sigsys_launcher` installs no `NEW_LISTENER` fd**, which is why it is reentrancy-safe and why `make test` uses it rather than the tier-2 binary. Changing that changes what the test suite actually exercises.
- **Interposed libc functions must be complete and consistent** — `open`, `openat`, `fopen`, `access`, `faccessat`, `stat`, `lstat` resolved through `dlsym(RTLD_NEXT, …)`. A partially-implemented interposition sends some calls through and not others.
- **Signal and notification handlers stay async-signal-safe** — no `malloc`, no `stdio` in a handler.
- **No dependencies beyond libc and the Linux kernel headers**, compiled with `clang` into `build/`.

### Commands a reviewer should be able to quote

```bash
make          # libtermux-etc-redirect.so, termux-etc-seccomp, termux-etc-mount, sigsys_launcher
make test     # tier 1 unit, tier 2 integration + faccessat2 SIGSYS + clone-race + reentrancy,
              # tier 3 integration + reentrancy
make install
make clean
```

### Dispatch tables over `switch`

See [Mapper Design Pattern](https://github.com/rios0rios0/guide/wiki/Mapper-Design-Pattern). Two or three stable cases may stay a
`switch`. Four or more, or a set that grows with features, becomes a map from key to handler
so that adding a case is a new entry rather than an edit to the dispatcher. Flag new
`switch`/`if-else` chains that dispatch on a string or enum key.

## Tests

See [Tests](https://github.com/rios0rios0/guide/wiki/Tests).

- `make test` is the gate and it is tiered — a change to any tier must run the whole suite, because the tiers share the redirect table.
- The multithreaded clone-race and reentrancy tests exist because both bugs shipped once; a change to the ptrace or seccomp path must keep them green and, ideally, add a case.
- Test fixtures live under `test/`, including `test/test-terraform` for a real Go binary exercise.

### Rules that hold for every test in this repository

- **BDD blocks are mandatory.** Every test body carries `// given` / `// when` / `// then`
  (`# given` / `# when` / `# then` in Python) delimiting preconditions, the action, and the
  assertions. A test without them is a finding.
- **Descriptions follow the layer.** Commands: `"should call <listener> when …"`.
  Controllers: `"should respond <HTTP_STATUS> when …"`. Services and repositories:
  `"should … when …"`, with at least one success and one failure case per public method.
- **Mock libraries are banned** — the category, not just the names: `testify/mock`,
  `golang/mock`, `mockery`, `go-sqlmock`, `httpmock`, `gock`, Mockito, EasyMock, PowerMock,
  `unittest.mock`, `pytest-mock`, `responses`, `requests-mock`, `jest.mock()` module mocking,
  `sinon`, `nock`, `testdouble`. Doubles are hand-rolled: stubs return canned answers,
  in-memory implementations hold state, and a spy that records calls is used only when
  nothing observable exists. Reaching for a mock library almost always means a port is
  missing — extract the interface the consumer needs instead.
- **Driver-level and transport-level mocks are the worst case.** SQL and HTTP behaviour is
  proven against the real thing: a real database with the real migrations for stores, a real
  local test server for outbound clients. Those are not mocks; they are real implementations
  under test control.
- **Builders construct test data.** Complex entities and DTOs come from builders, not from
  long literal structs repeated across files.
- A test deleted, skipped, or weakened to make a change pass is a Critical finding.

## Documentation and change control

See [Documentation & Change Control](https://github.com/rios0rios0/guide/wiki/Documentation-&-Change-Control) and
[CHANGELOG Formatting](https://github.com/rios0rios0/guide/wiki/CHANGELOG-Formatting).

This repository uses **chlog fragments**. `CHANGELOG.md` is generated and is never edited by
hand.

- Every change ships a fragment created with `chlog new --kind <Kind> --body "…"`, staged in
  the **same commit** as the code. Kinds: `Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`.
- A backward-incompatible change to the public interface additionally carries `--breaking`.
  The kind alone never triggers a major bump.
- A hand-edited `CHANGELOG.md`, or a code change with no fragment under
  `.changes/unreleased/`, is a **Critical** finding — `chlog check` fails the build for it.
- Fragment bodies start with a lowercase verb in simple past tense, capitalise proper nouns
  (GitHub, Go, Docker), and wrap code identifiers and versions in backticks.
- `README.md` is updated whenever usage, setup, configuration, or architecture changes;
  `.github/copilot-instructions.md` and `CLAUDE.md` whenever the workflow, commands, or
  structure changes. Documentation and code ship in one commit.

## Git Flow and pull-request hygiene

See [Git Flow](https://github.com/rios0rios0/guide/wiki/Git-Flow) and [Merge Guide](https://github.com/rios0rios0/guide/wiki/Merge-Guide).

- Branch names are `feat/`, `fix/`, `refactor/`, `chore/`, `test/`, or `docs/` followed by a
  ticket ID or a short slug — `feat/TICKET-000`, `fix/input-mask`.
- Commit subjects are `type(SCOPE): message`: simple past tense (`added`, `fixed`, `changed`,
  `removed`), lowercase first word, no trailing period, code identifiers in backticks.
- Branches are synchronised with `git rebase`, never `git merge`. A merge commit from the
  default branch inside a feature branch is a finding.
- Breaking changes are flagged in **three** places: the commit footer
  (`**BREAKING CHANGE:** …`), the changelog, and the pull-request description. One or two of
  the three is not enough.
- Versions follow [SemVer](https://semver.org/): MAJOR for incompatible changes, MINOR for
  features, PATCH for fixes.

## Security

See [Security](https://github.com/rios0rios0/guide/wiki/Security).

- **No hard-coded secrets.** API keys, tokens, passwords, and private keys belong in
  environment variables or a secret manager — never in source, tests, fixtures, or the
  changelog. A secret that reaches a commit must be rotated, not merely deleted.
- **Never write a PEM header sentinel or a realistic key shape into a fixture**
  (`ghp_…`, `sk-…`, `AKIA…`, `xoxb-…`, JWT-shaped strings, or the dashed `BEGIN …` banners).
  Gitleaks matches the shape, not the value, so a placeholder that merely *looks* like a
  credential fails the pipeline. Use inert placeholders such as `fixture-token-placeholder`.
- **Suppressions must be justified.** Entries in `.gitleaksignore`, `.trivyignore`,
  `.semgrepignore`, or `.codeql-false-positives` need a fingerprint, a dated comment, and a
  reason. A suppression added to silence a real finding is a Critical.
- Validate and sanitise every external input; use parameterised queries; apply least
  privilege; keep secrets out of logs.
- Dependency manifest changes are reviewed for new transitive vulnerabilities. When a fix
  exists, bump the version rather than suppressing the finding.

## What not to flag

A review that raises noise gets ignored. Do not report these:

- The duplication of `REDIRECT_TABLE` across tiers — it is deliberate.
- The absence of a linter configuration for C in this repository.
- Anything the guide does not require and this file does not list, unless it is a genuine correctness or security defect — say so plainly and label it a Suggestion.

## Review output format

```
## Code review: <branch or PR>

### Critical (must fix before merge)
- `path/to/file.ext:LINE` — <what is wrong> — violates <rule> (<guide page or repo file>)

### Warning (should fix)
- `path/to/file.ext:LINE` — <what is wrong> — violates <rule>

### Suggestion (optional)
- `path/to/file.ext:LINE` — <improvement>

### Change-control checklist
- [ ] Changelog entry present for every behavioural change
- [ ] `README.md` updated if usage, setup, or architecture changed
- [ ] `.github/copilot-instructions.md` and `CLAUDE.md` updated if the workflow, commands, or structure changed
- [ ] Commit messages follow `type(SCOPE): message` in simple past tense
- [ ] Breaking changes flagged in the commit footer, the changelog, and the PR description

### Verdict: APPROVE / REQUEST CHANGES
<one paragraph: the blocking findings, or why the change is ready>
```

## Severity

| Severity       | Use for                                                                                                                            |
|----------------|------------------------------------------------------------------------------------------------------------------------------------|
| **Critical**   | Broken dependency direction, a leaked secret, an injection or authentication flaw, a missing changelog entry, a banned mock library, a load-bearing invariant broken, a test deleted rather than fixed. |
| **Warning**    | Naming that departs from the guide, a missing test for a new branch of logic, an unexplained magic value, a stale README or instructions file, a `switch` that should be a map. |
| **Suggestion** | Readability, consistency with neighbouring modules, and performance ideas that no rule mandates.                                     |

Rank findings most severe first, and state plainly when nothing blocks the merge — an empty
Critical section is a valid, useful review.
