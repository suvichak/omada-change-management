# Notes for AI assistants

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. The hard rules:

- Push work only to the **private** remote `origin` (`suvichak/omada-change-management-private`), on a
  branch named `ai/<short-topic>`, and open the pull request there against `main`.
- **Never push to the `public` remote** (`suvichak/omada-change-management`), never push to `main`
  directly, and never force-push `main`. The maintainer publishes `main` after merging.
- Run `git config core.hooksPath .githooks` once per clone, and never commit with `--no-verify`.
- Run `python -m pytest -q tests` before pushing, and fill in every item of the PR template.
- Nothing personal in any commit: no secrets, real hostnames, domains, public IPs, MACs, site IDs
  or usernames. If one slips into a commit, rewrite the branch. Don't just add a fix commit on top.
