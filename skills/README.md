# Agent skills

Skills that teach an AI coding agent (Claude Code, Cursor, Copilot, or any
tool that reads the [Agent Skills](https://agentskills.io/) format) how to
build on Midnight Passport correctly. Each skill is a directory with a
`SKILL.md` entry point and a `rules/` folder the agent reads on demand.

| Skill | Use it when |
| --- | --- |
| [`midnight-passport/`](midnight-passport/) | building a web app that signs users in through Passport, asks for a payment, verifies a signed redirect reply, issues an item to a user, or wants to be listed in Passport |

## Install

**Claude Code** — copy the skill directory into your project (or your home
directory for every project) and it is picked up on the next session:

```sh
mkdir -p .claude/skills
cp -R skills/midnight-passport .claude/skills/
```

**Cursor** — copy `skills/midnight-passport` into `.cursor/skills/`, or add
`SKILL.md` and the `rules/*.md` files as project rules.

**Anything else** — point the agent at `skills/midnight-passport/SKILL.md`;
it links to everything it needs and names the code it was checked against.

## Keeping it true

The skill states what the code in this repository does as of the date in its
front matter. When `packages/connect` changes, the rule that describes the
changed surface is updated in the same pull request — a skill that drifts
from the code teaches an agent to write bugs with confidence.
