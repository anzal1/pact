# Pact Capability Conventions

**Status:** Draft v0.1  
**Purpose:** Shared vocabulary so agents can compose across providers

---

## Why conventions matter

Pact's capability system is flexible by design — `resource:action,constraint=value` can express anything. But flexibility without conventions leads to fragmentation. If GitHub uses `repo:read` and GitLab uses `repository:fetch`, an agent that works with both needs a translation layer for every pair of providers.

These conventions don't restrict what providers can use. They propose a **starting vocabulary** for common domains so the ecosystem doesn't fragment before it forms.

## Capability format recap

```
resource:action                         # basic
resource:action,constraint=value        # constrained
resource:sub:action,constraint=value    # hierarchical
resource:*                              # wildcard (all actions)
*                                       # full access (dangerous)
```

**Narrowing rule:** A delegated capability must be covered by the delegator's capability. Wildcards narrow to specifics. Constraints can only tighten, never relax.

---

## Domain conventions

### 1. Code hosting

Providers: GitHub, GitLab, Bitbucket, Gitea, etc.

| Capability | Meaning |
|---|---|
| `repo:read` | Read repository content, metadata, branches |
| `repo:read,repo=owner/name` | Read a specific repository |
| `repo:read,repo=owner/*` | Read any repo in an org/owner |
| `repo:write` | Push commits, create branches |
| `repo:write,repo=owner/name,branch=feature/*` | Push to feature branches only |
| `repo:delete` | Delete repositories |
| `repo:pr:create` | Create pull/merge requests |
| `repo:pr:create,repo=owner/name` | Create PRs in a specific repo |
| `repo:pr:merge` | Merge pull/merge requests |
| `repo:pr:review` | Submit reviews and comments |
| `repo:issue:create` | Create issues |
| `repo:issue:comment` | Comment on issues |
| `repo:issue:close` | Close issues |
| `repo:release:create` | Create releases/tags |
| `repo:webhook:manage` | Create/edit/delete webhooks |
| `repo:*` | All repository operations |
| `repo:*,repo=owner/name` | All operations on one repo |

**Design notes:**
- `repo` not `repository` — short, unambiguous, matches the dominant convention (GitHub, Gitea, Bitbucket all use "repo" internally).
- Hierarchical sub-resources (`repo:pr`, `repo:issue`) rather than flat (`pr:create`), because `repo:*` should cover everything about repositories.
- The `repo=` constraint uses `owner/name` format, matching GitHub/GitLab conventions.

### 2. Deployment

Providers: Vercel, Netlify, Railway, Render, Fly.io, AWS, GCP, Azure, etc.

| Capability | Meaning |
|---|---|
| `deploy:create` | Trigger a deployment |
| `deploy:create,env=staging` | Deploy to staging only |
| `deploy:create,env=production` | Deploy to production |
| `deploy:create,project=myapp` | Deploy a specific project |
| `deploy:promote` | Promote a deployment (staging → production) |
| `deploy:rollback` | Rollback to a previous deployment |
| `deploy:read` | View deployment status and logs |
| `deploy:delete` | Remove/cancel deployments |
| `deploy:config:read` | Read deploy configuration |
| `deploy:config:write` | Modify deploy configuration |
| `deploy:env:read` | Read environment variables |
| `deploy:env:write` | Set environment variables |
| `deploy:*` | All deployment operations |
| `deploy:*,env=staging` | All deploy operations, staging only |

**Design notes:**
- `env=` is the critical constraint. The most common real-world narrowing is "this agent can deploy to staging but not production."
- `deploy:env:*` (environment variables) is separate from `deploy:create` because reading secrets is a different privilege than deploying code.

### 3. Storage / databases

Providers: S3, GCS, R2, PlanetScale, Supabase, Neon, Redis, etc.

| Capability | Meaning |
|---|---|
| `storage:read` | Read objects/files |
| `storage:read,bucket=my-bucket` | Read from a specific bucket |
| `storage:read,prefix=public/*` | Read objects matching a prefix |
| `storage:write` | Write/upload objects |
| `storage:write,bucket=my-bucket` | Write to a specific bucket |
| `storage:delete` | Delete objects |
| `storage:list` | List buckets/objects |
| `storage:*` | All storage operations |
| `db:read` | Read/query database |
| `db:read,table=users` | Read a specific table |
| `db:write` | Insert/update records |
| `db:write,table=logs` | Write to a specific table |
| `db:schema:read` | Read schema/migrations |
| `db:schema:write` | Modify schema (DDL) |
| `db:delete` | Delete records |
| `db:*` | All database operations |

**Design notes:**
- `storage` for object/file stores, `db` for databases. Clear separation.
- `bucket=` and `table=` are the natural narrowing constraints.
- `prefix=` for path-based scoping in object stores.

### 4. Communication

Providers: Email (SendGrid, Resend, SES), Slack, Discord, Teams, etc.

| Capability | Meaning |
|---|---|
| `email:send` | Send emails |
| `email:send,to=*@mycompany.com` | Send only to company addresses |
| `email:send,to=person@example.com` | Send to one recipient |
| `email:read` | Read inbox / received emails |
| `email:*` | All email operations |
| `chat:send` | Send chat messages |
| `chat:send,channel=engineering` | Send to a specific channel |
| `chat:send,channel=*` | Send to any channel |
| `chat:read` | Read chat messages |
| `chat:react` | Add reactions |
| `chat:*` | All chat operations |
| `notification:send` | Send push/webhook notifications |
| `notification:*` | All notification operations |

**Design notes:**
- `to=` for email scoping, `channel=` for chat scoping.
- Glob patterns in constraints (`*@mycompany.com`) are supported by Pact's capability matching engine.

### 5. AI / ML

Providers: OpenAI, Anthropic, Google, Replicate, HuggingFace, etc.

| Capability | Meaning |
|---|---|
| `model:inference` | Run model inference |
| `model:inference,model=gpt-4*` | Restrict to specific model family |
| `model:inference,cost<100USD` | Cost cap per request |
| `model:finetune` | Fine-tune models |
| `model:embed` | Generate embeddings |
| `model:read` | List/inspect models |
| `model:*` | All model operations |

**Design notes:**
- `cost<` uses the numeric constraint syntax (`max=`) for budget caps.
- Model scoping via `model=` constraint with glob support.

### 6. Compute / infrastructure

Providers: AWS, GCP, Azure, DigitalOcean, etc.

| Capability | Meaning |
|---|---|
| `compute:create` | Launch VMs/containers |
| `compute:create,region=us-east-1` | Region-restricted |
| `compute:create,size=small` | Size-restricted |
| `compute:stop` | Stop running instances |
| `compute:terminate` | Terminate/delete instances |
| `compute:ssh` | SSH access to instances |
| `compute:read` | List/inspect instances |
| `compute:*` | All compute operations |
| `dns:read` | Read DNS records |
| `dns:write` | Create/modify DNS records |
| `dns:write,zone=example.com` | Scoped to a domain |
| `dns:*` | All DNS operations |
| `secret:read` | Read secrets (dangerous — use narrow constraints) |
| `secret:read,name=API_KEY` | Read a specific secret |
| `secret:write` | Write/create secrets |
| `secret:*` | All secret operations |

**Design notes:**
- `secret:*` is intentionally separate from everything else. Reading secrets is the most sensitive operation — always constrain by `name=`.
- `region=` for geographic restrictions.

### 7. Filesystem / workspace

For local tool-use agents (Copilot, Cursor, Aider, etc.)

| Capability | Meaning |
|---|---|
| `fs:read` | Read files |
| `fs:read,path=/src/*` | Read only in /src |
| `fs:write` | Write/create files |
| `fs:write,path=/src/*,ext=*.go` | Write only Go files in /src |
| `fs:delete` | Delete files |
| `fs:exec` | Execute commands |
| `fs:exec,cmd=go\ test*` | Only run go test commands |
| `fs:*` | All filesystem operations |

**Design notes:**
- `path=` for directory scoping, `ext=` for file type restrictions.
- `fs:exec` is the most dangerous — always constrain with `cmd=`.
- Backslash-escape spaces in constraint values.

### 8. Generic API access

Fallback for providers that don't fit the above domains.

| Capability | Meaning |
|---|---|
| `api:read` | GET requests |
| `api:write` | POST/PUT/PATCH requests |
| `api:delete` | DELETE requests |
| `api:*` | All HTTP methods |
| `api:read,path=/v1/users/*` | Scoped to a path |

---

## Convention rules

1. **Resources are lowercase, colon-separated:** `repo:pr`, `deploy:env`, not `Repo.PullRequest`
2. **Actions are verbs:** `read`, `write`, `create`, `delete`, `send`, `execute`
3. **Constraints are nouns:** `repo=`, `env=`, `bucket=`, `channel=`
4. **Wildcards mean "all":** `repo:*` = all repo actions, `repo=owner/*` = all repos in owner
5. **Hierarchical before flat:** Prefer `repo:issue:create` over `issue:create` so `repo:*` covers everything
6. **Short, unambiguous resource names:** `repo` not `repository`, `db` not `database`, `fs` not `filesystem`
7. **Use constraints for narrowing, not new resources:** `deploy:create,env=staging` not `deploy:staging:create`
8. **Never grant `*` in production:** Full wildcard is for development/testing only

## Narrowing examples

A human delegates broad access. Each sub-delegation narrows:

```
Human → CI Agent:      repo:*,repo=myorg/*
CI Agent → Deploy Bot:  repo:read,repo=myorg/frontend  +  deploy:create,env=staging
Deploy Bot → Notifier:  chat:send,channel=deploys
```

Each step is strictly narrower. Pact enforces this cryptographically — a sub-delegation that exceeds its parent's scope fails verification.

## For providers implementing Pact

Your provider doesn't need to support all these conventions. Pick the ones relevant to your domain:

1. **Document your capabilities** in your API docs: "We accept these Pact capability strings."
2. **Map to your internal permissions** using `CapabilityMapper` (see `bridge.go`).
3. **Validate with `RequiredCapability`** in your middleware config.
4. **Register your conventions** by opening a PR to this file.

The goal is convergence through usage, not a committee. Ship what makes sense, and the conventions that work will survive.

---

## Contributing conventions

To propose new capability conventions:

1. Open a PR adding your domain to this file.
2. Include at least: resource names, common actions, 2-3 constraint examples.
3. Explain why existing conventions don't cover your use case.
4. Show a narrowing example (broad → narrow delegation).

Conventions are accepted when two or more providers agree to use them.
