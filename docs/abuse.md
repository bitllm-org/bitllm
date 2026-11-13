# When someone abuses your node

An open server answers anyone. Most of them write code or chat. Now and then one will use your GPU
for something you do not want to power: an attack on systems they have no permission to test, or
plain bulk load that crowds everyone else out. This page is what a host can do about it, in the
order that worked the first time it happened on this network (November 2026: an automated
penetration-testing framework ran against a bank's production systems through one open server, and
took more than half of that server's output for three days before anyone looked).

## What you can and cannot see

- `receipts.jsonl` in the data directory lists every job you served: time, model, token counts and
  a client id. **That client id is a pseudonym**, one per client per server, rotated every 30 days.
  It tells you how much one client used. It does not tell you which node it is.
- `--attribution-log` writes the missing link: for each job, the node id and address of the node
  that sent it, next to the pseudonym. It is off by default. Turn it on before you need it; it
  cannot be filled in afterwards.
- Your server sees every prompt in plaintext, like any inference provider. The node does not store
  prompts. Look at them only when the numbers give you a reason to, and only at the node in
  question.

## 1. Notice

Look at who uses the most. A healthy server has many small clients and a few large ones. Two
things are worth a second look:

- one client taking a large share of the day, every day;
- a new client that is large from its first day.

Size alone proves nothing. Coding agents routinely send prompts of 100K to 300K tokens, and half
of the ordinary requests on a busy server are that large. Do not block on prompt length or volume.

## 2. Look, narrowly

If one client stands out, look at one or two of its requests on the way to your model server. The
tool list is usually enough: a coding agent carries `read`, `edit`, `bash`, `grep`; an attack
framework carries tools named after what it does. A generic agent with a shell can do anything, so
a clean tool list is not proof of innocence, but a tool list full of scanners, credential
spraying and exploit helpers aimed at named production hosts is a clear answer.

You will often be unable to tell whether the work is authorized. Prompts that say "authorized
engagement" are written by the person sending them. You do not have to decide. You only have to
decide whether you want to power it.

## 3. Stop serving that node

```sh
bitllm ... --deny 12D3KooW...   # repeatable; the node id from attribution.jsonl
```

A denied node gets a permanent refusal before any slot or quota is touched, and `GET /status`
counts the refusals under `refusals.deny`. Everyone else is served as before. Prefer this to
dropping `--open`: closing the server punishes every other user for what one did.

Know the limit: node ids are free. Someone determined can make a new one in a minute, and a new id
also starts with a fresh daily quota. `--deny` stops the node that is not paying attention and
shows you who comes back on purpose. `--free-daily` caps what each id can take per day and
`--open-daily` caps all uninvited nodes together. If the same work returns under new ids, the
answer is not a longer deny list but a rule that does not depend on identity: serve uninvited
nodes less, or serve them a different model than members.

## 4. Keep what you saw

If the traffic targeted someone, they may need to know what was done. Before you restart anything,
copy `receipts.jsonl` and `attribution.jsonl`, and if you looked at requests, keep those too. Note
the times in UTC and hash the files. Captured prompts can contain other people's secrets
(passwords, keys, card numbers the attacker collected), so keep the copy readable only by you, do
not publish it, and do not send it unencrypted.

## 5. Tell the target

If a named organization was on the receiving end, write to its security contact (look for
`/.well-known/security.txt` on its site). Say what you are, what you saw and when, which addresses
the requests came from, and what you did. Say plainly that you cannot tell whether the work was
authorized. Leave secrets out of the first message and offer the material encrypted, on request.
You were a carrier, not the attacker, and reporting it yourself is better for everyone than being
found in their logs.

## What not to do

- Do not read everyone's prompts to find the one bad client. Start from usage, then look narrowly.
- Do not publish node ids, addresses or captured prompts.
- Do not keep serving while you wait to find out whether it was authorized.
