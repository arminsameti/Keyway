# Contributing to Keyway

Thanks for helping. Bug reports, ideas and pull requests are all welcome.

## Report a bug or ask for a feature

Open an [issue](https://github.com/arminsameti/Keyway/issues/new/choose). For a bug, say which Keyway version and macOS version you use, which engine and protocol the server runs on, and what you expected to happen. Remove server addresses, keys and subscription URLs from anything you paste.

For a security problem, do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Send a change

1. Fork the repo and branch from `master`.
2. Build and run it with the steps in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
3. Keep the change focused. A small pull request is reviewed faster than a large one.
4. Run `make vet && make lint && make smoke` before you open the pull request, and `make e2e` when you touched engine, chain or connect logic.
5. Describe what changed and why. Add a screenshot for a visible change (`make snapshots` renders every screen).

Pull requests are squash-merged, so the title becomes the commit message. Write it as a short sentence, such as `Add a Fallback group type`.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how the code is laid out.

## Conduct

Be kind and assume good faith. See the [Code of Conduct](CODE_OF_CONDUCT.md).
