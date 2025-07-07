# 🔐 pacli - Your Personal Secrets Managment CLI

This is a simple CLI tool to help for managing secrets locally with focusing on high privacy concerns. Biggest disadvantage of using online tool is that sometimes their password got stolen by hackaers that causes your password leaked and available on the internet.

## Available Commands

```command
❯ pacli --help
Usage: pacli [OPTIONS] COMMAND [ARGS]...

  🔐 pacli - Personal Access CLI for managing secrets...

Options:
  --help  Show this message and exit.

Commands:
  add                Add a secret with LABEL.
  change-master-key  Change the master password wihtout losing existing...
  delete             Delete a secret by LABEL.
  delete-by-id       Delete a secret by its ID.
  get                Retrieve secrets by LABEL.
  get-by-id          Retrieve a secret by its ID.
  init               Initialize pacli and set a master password.
  list               List all saved secrets.
  version            Show the current version of pacli.
```

## Install

```sh
pip install pacli-tool
```

## Display Format

- For credential: `username:password`

## Copy Into Clipboard

To copy secrets directly into clipboard use `--clip` option. Example:

```sh
pacli get google --clip
```
