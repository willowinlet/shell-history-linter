# shell-history-linter

Your `.bash_history` and `.zsh_history` are plaintext files that quietly
accumulate every API key you ever exported inline, every `curl | bash`
you ran to install something, and every `rm -rf` you typed half-awake.
They get backed up, synced to other machines, and read by anything
running as your user. Nobody audits them until something goes wrong.

`histlint` scans a history file and reports the specific problems it
finds, with a file, line, and column pointing at exactly the part of the
command that's the issue — not just "line 42 looks bad."

## Usage

```
$ go build -o histlint .
$ ./histlint ~/.zsh_history
```

Example output:

```
/Users/you/.zsh_history:118:8: error [dangerous-rm]: recursive forced delete of / would wipe far more than one directory
    |
118 | sudo rm -rf /
    |             ^
    = help: scope the path before rerunning this, e.g. `rm -rf -- ./specific/dir`, or drop -f and confirm each removal

/Users/you/.zsh_history:203:23: warning [plaintext-secret]: value assigned to STRIPE_API_KEY looks like a live credential sitting in plaintext history
    |
203 | export STRIPE_API_KEY=abcd1234efgh5678ijkl
    |                        ^^^^^^^^^^^^^^^^^^^^
    = help: history files are rarely encrypted and often synced or backed up; rotate this credential and load secrets from a gitignored env file instead

/Users/you/.zsh_history:340:1: warning [pipe-to-shell]: output of curl/wget is piped straight into bash without ever being inspected
    |
340 | curl -sL https://example.com/install.sh | bash
    |                                            ^^^^
    = help: download to a file and read it first: the remote script can differ from what you reviewed by the time it runs again
```

Exit codes: `0` if no findings, `1` if findings were reported, `2` if a
file couldn't be read.

## What it checks today

- `dangerous-rm` — `rm` combined with recursive and force flags, targeting
  `/`, `~`, `$HOME`, or a bare `*`.
- `pipe-to-shell` — `curl`/`wget` output piped into `sh`/`bash`/`zsh`/`dash`/`ksh`.
- `plaintext-secret` — a shell variable assignment whose name looks like a
  key/token/secret/password and whose value isn't an obvious placeholder.

## History file formats

Plain history (one command per line) and zsh's extended format
(`: <epoch>:<duration>;<command>`) are both handled — reported columns
always point into the command itself, skipping the timestamp prefix when
present.

## Limitations (for now)

- Each history line is linted independently; a command continued across
  lines with a trailing `\` is not reassembled.
- Pipe and token splitting is whitespace/`|`-based and doesn't understand
  quoting, so a `|` or space inside a quoted string can throw off column
  math for that line.
- No config file yet — all three rules always run.

## License

MIT, see [LICENSE](LICENSE).
