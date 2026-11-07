# MCP server

The MCP server lets agents find, read and write Strongbox data without becoming a path around policy.
It is a client of the REST API: it holds no keys and no database access, and every call it makes is
authorized and audited by the API as **the agent acting on behalf of a user**.

## Tools

| Tool | Kind | Notes |
|---|---|---|
| `whoami` | read | Effective identity, including the agent as `actor` |
| `list_collections` | read | Only collections the user and agent may both see |
| `describe_collection` | read | JSON Schema and filterable fields |
| `query_records` | read | Exact match on indexed fields, cursor paging; returns a roll-up marking |
| `get_record` | read | |
| `create_record` | write | Marking defaults to the collection's; may only be more restrictive |
| `update_record` | write (destructive hint) | Requires `expected_version` |
| `list_blobs` | read | Metadata only |
| `get_blob_metadata` | read | |
| `read_blob_text` | read | Text types only, size-capped (`STRONGBOX_MCP_MAX_READ_BYTES`, default 256 KiB) |
| `put_blob_text` | write | Stores generated text as an encrypted blob |

There are no delete or shred tools. Destructive operations stay with people and services.

Every CUI result carries its `marking` and a `handling` note, and the server instructions tell the model
to carry markings forward and to treat stored content as untrusted input.

## Content withholding

Whether CUI may enter a model's context depends on where the model runs, not on who the user is.
Each agent principal has `llm_boundary_authorized`:

- **false (default):** the agent can see that objects exist, their markings and metadata, and can create
  data, but CUI content comes back as `content_withheld: true`. UNCONTROLLED content is returned normally.
- **true:** set this only for an agent whose model runs inside your authorized boundary, for example an
  open-weight model served on GKE in the same Assured Workloads folder, or a managed model endpoint you
  have confirmed is in scope for your regime.

Register separate agent principals per model deployment so this stays accurate as you add models.

## Identity

**stdio** (one person, local client):

```bash
STRONGBOX_MCP_API_URL=https://strongbox.internal
STRONGBOX_MCP_TOKEN=<agent's token>               # or STRONGBOX_MCP_GOOGLE_AUDIENCE=strongbox-api
STRONGBOX_MCP_ON_BEHALF_OF=<the user's token>
strongbox mcp
```

**streamable HTTP** (shared server): each MCP client sends the user's bearer token. The server verifies it
(issuer, audience from `STRONGBOX_DELEGATION_AUDIENCES`), then calls the API with its own Google ID token
plus `X-On-Behalf-Of: <user token>`. Set `STRONGBOX_MCP_PUBLIC_URL` to the URL clients use and
`STRONGBOX_MCP_ALLOWED_HOSTS` to enable DNS-rebinding protection.

```bash
strongbox mcp --transport streamable-http --host 0.0.0.0 --port 8080
```

## Example session

A user asks an agent outside the boundary: "Which open NCRs reference TR-1042?"

1. `query_records(collection="ncr", filters={"part_number": "TR-1042"})`
2. The API checks the user (U.S. person, SP-EXPT) ∩ agent, filters results, and audits
   `record.query` with actor `agent:claude`, on behalf of the user.
3. The agent receives record ids, versions, timestamps and `CUI//SP-EXPT` markings with
   `content_withheld: true`, and replies with the list and links for the user to open in a cleared tool.

The same question through an agent registered inside the boundary returns the record contents, still
marked.
