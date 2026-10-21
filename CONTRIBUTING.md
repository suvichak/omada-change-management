# Contributing

## How changes flow

```
private source ──tools/export-public──▶ dev clone, branch ai/<topic>
                                          │ push
                                          ▼
               suvichak/omada-change-management-private (PRIVATE)   ← every work branch and PR lives here
                                          │ PR → CI (tests, gitleaks, private patterns) → review → squash-merge
                                          ▼
               suvichak/omada-change-management (PUBLIC)            ← main only, pushed by the maintainer
```

- **Work branches never go to the public repo.** Every branch and every pull-request commit in a
  public GitHub repo is public, and a PR's commits stay reachable even after the branch is deleted.
- **Squash-merge** pull requests, so only reviewed end states reach `main`.
- The public `main` is updated by hand after a merge: `git pull origin main && git push public main`.

## One-time set-up of a clone

```bash
git clone git@github.com:suvichak/omada-change-management-private.git omada-change-management
cd omada-change-management
git remote add public git@github.com:suvichak/omada-change-management.git
git config core.hooksPath .githooks     # pre-commit: gitleaks + private patterns; pre-push: public gets main only
```

The hooks need `gitleaks` on `PATH` or in `~/bin`. The private-identifier list lives outside the
repo, in `~/.config/omada-change-management/private-patterns` (one extended regex per line), so the
list itself is never published. CI reads the same list from the `PRIVATE_PATTERNS` secret.

## Making a change

1. `git switch -c ai/<short-topic> origin/main`
2. Change the code (or run `tools/export-public` from the private source into this clone).
3. `python -m pytest -q tests`
4. Commit. The pre-commit hook scans the staged lines.
5. `git push -u origin ai/<short-topic>` and open a pull request against `main` on the **private** repo.
   Fill in the template.
6. The maintainer reviews, CI must pass, then squash-merge.

## If something private was committed

- **Not pushed yet:** fix it and rewrite the commit (`git commit --amend` or an interactive rebase).
- **Pushed to the private repo:** rewrite the branch and force-push it. Close the PR and open a new one.
  The private repo's PR refs keep the old commit, but only the maintainer can see it.
- **Pushed to the public repo:** treat it as leaked. **Rotate the key or token first**, then clean up.
  Deleting the commit doesn't un-publish it.

## Rules

- No keys, tokens, passwords, cookies or `.env` contents. Use `deploy/ct/env.example` placeholders.
- No real hostnames, domains, public IPs, MACs, site IDs or usernames. Use `example.com`, `alice`,
  `AA-BB-CC-DD-EE-FF`, `0123456789abcdef01234567`, and RFC 1918 / RFC 5737 addresses.
- No proposals, packet captures, databases or TP-Link spec files.
