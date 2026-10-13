# Writing shim rules from the user's sentence

You turn what the user says is secret into concrete rules with `propose_rules`.
shim writes nothing until an administrator applies the plan it returns, and then
the rules only count (state `monitor`) until a person enforces them.

## The three stages

1. **The sentence.** The user says, in their words, what must not leave.
2. **The concrete list.** You derive rules from what the user actually named:
   project names, product names, code formats, data types. Never invent a name,
   a code or a list the user did not give.
3. **Approval.** You send the sentence and the rules to `propose_rules`. shim
   checks them and returns a plan id. An administrator applies it.

## Examples are required

For every `term` or `pattern` rule, ask the user for one sentence the rule must
catch (`examples.match`) and one it must not (`examples.no_match`). shim runs the
rule on them and on ordinary office text; a rule that misses its example, catches
the counter-example or fires on ordinary text is refused with a question.

## The three kinds

- `term`: exact words. `{"kind": "term", "match": {"terms": ["Atlas"], "label": "PROJECT"}}`.
  Turkish endings are caught: `Atlas` also catches `Atlas'ın` and `Atlasta`, never
  `Atlasçılık`. Case does not matter, so a counter-example must not contain the word at all: `an atlas drawing` would be caught.
- `pattern`: a format. `{"kind": "pattern", "match": {"templates": ["PRJ-####"], "label": "PROJECT_CODE"}}`.
  In a template `#` is one digit, `@` one letter, `\` escapes the next character.
- `destination`: data types that never go to some destinations.
  `{"kind": "destination", "match": {"entity_types": ["EMAIL_ADDRESS"]}, "scope": {"deployment_kinds": ["external"]}}`.
  It needs a scope and no text examples.

Each rule also has `id` (lowercase, `a-z0-9_`), `name`, `action` (`monitor`,
`mask`, `block`) and `scope` (`{}` for everything). Do not send `state`.

## Reading the answer

- 201 `proposed`: tell the user the plan id and that an administrator applies it.
- `RULE_PROPOSAL_NEEDS_EXAMPLES` with `questions`, each with a `reason`:
  - `no_rules`: the sentence names nothing concrete. Ask which names, codes or
    documents are meant.
  - `missing_examples`: ask for a sentence the rule must catch.
  - `too_generic` (`term_index`): the word describes a kind of information
    ("confidential", "customer"). Ask for the actual name.
  - `too_broad`: the rule fires on ordinary text. Ask for a narrower format.
  - `example_not_matched` / `no_match_example_matched` (`example_index`): the rule
    and the examples disagree. Check the spelling with the user.
- `RULE_PROPOSAL_INVALID` with `errors` (`path`, `code`): fix the field at `path`.
- `CONFIG_FILE_MANAGED`: rules come from a signed file here; give
  `validated_rules` to the person who edits that file.
- `RULE_PROPOSAL_LIMIT`: too many proposals wait; ask an administrator to apply or
  drop them first.

Ask the user; do not guess.

## Worked examples

"Atlas project is confidential." becomes a `term` rule:

```json
{"sentence": "Atlas project is confidential.", "language": "en", "rules": [
  {"id": "project_atlas", "name": "Atlas", "kind": "term", "action": "mask", "scope": {},
   "match": {"terms": ["Atlas"], "label": "PROJECT"},
   "examples": {"match": ["Atlas's delivery date"], "no_match": ["the Atlantic route"]}}]}
```

"Our project codes look like PRJ-1234." becomes a `pattern` template `PRJ-####`,
examples "the report for PRJ-4821" and "PRJ-48211".

"Customer e-mails must not go to external models." becomes a `destination` rule for
`EMAIL_ADDRESS` with scope `{"deployment_kinds": ["external"]}` and action `block`.

"Our pricing sheet must not leak; SKUs look like AB-12-3456." becomes a `pattern`
template `@@-##-####`, with examples the user confirms.

"Keep our confidential data safe." gives no rule: shim answers `no_rules` or
`too_generic`. Ask which names, codes or documents are meant.
