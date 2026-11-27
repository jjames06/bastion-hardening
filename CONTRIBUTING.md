# Contributing to Bastion

Thank you for helping make Bastion better. Bastion is a selective, safety-first hardening tool for a personal Windows 10 or 11 computer you administer. Issues, test reports and pull requests are welcome when they keep that promise.

## Before you open an issue

- Run a **Dry Run** first, and say whether you saw the problem in Dry Run, Apply, Quick Harden or Recovery.
- Name the Bastion version (for example v16.0) and your Windows version (Settings > System > About).
- Use an official download: [operationlockedin.com/bastion/download](https://www.operationlockedin.com/bastion/download) or [GitHub Releases](https://github.com/jjames06/bastion-hardening/releases/latest). You can check the zip against `SHA256SUMS.txt` on the release.
- If a game or program stops working after Apply, use the **Game / StrictHandle report** template.
- Remove personal paths, user names and computer names from any log lines you paste.

Private security reports: see [SECURITY.md](SECURITY.md). Please do not open a public issue for a security problem.

## Pull requests

- Keep every change reversible from Recovery, and show it in Dry Run before it is applied.
- Source lives in `src\Bastion.*.ps1`. Each file has a matching header; see [docs/CODEMAP.md](docs/CODEMAP.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Keep Windows PowerShell 5.1 compatibility.
- Do not add changes that are on by default when they can break common software. Opt-in is the rule.
- Update the handbook in `docs/wiki/` when behaviour changes.
- Do not bump the public version in a documentation-only change.
- Never commit keys, tokens, passwords or personal data.

## Code of Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Reports go to Info@operationlockedin.com.

## Licence

Contributions are accepted under the GNU General Public License version 3. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
