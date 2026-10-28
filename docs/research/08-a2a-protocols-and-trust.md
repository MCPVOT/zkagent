# 08 — Agent-to-Agent (A2A) Interoperability and Trust

**As of:** 2026-10-28. Spec versions quoted are the ones fetched that day.
**Slice owner:** protocol landscape + academic trust/delegation literature + where ZK adds a guarantee. Proving-stack survey (see 01), repo audit (04) and protocol design (05) are out of scope.
**Method:** direct fetch of primary specification pages (a2a-protocol.org, modelcontextprotocol.io, google-agentic-commerce.github.io/AP2, agentnetworkprotocol.com, docs.agntcy.org, x402 spec on GitHub); `gh api` / GitHub REST for A2A release dates; arXiv API (Atom, stdlib parse) for papers, then per-ID abstract fetch. Citation counts were mostly unavailable — Semantic Scholar returned HTTP 429 on nearly every request from this host, so **no citation counts are reported** except the two noted in §4.5.

**One-line read:** the interoperability layer converged fast on *transport and discovery* (A2A v1.0 is stable and now sits under the same foundation as MCP), but every specification in the stack deliberately stops at *"authorization is implementation-specific."* The academic literature has independently converged on the same diagnosis — 2026 produced a dozen papers on agent delegation, attenuation and attestation, and the most rigorous of them conclude that no existing standard alone covers the requirement set. The open surface is not messaging. It is proving, to a party that trusts neither the agent nor its host, that a specific action fell inside a specific human's delegation — which is exactly the object our circuit already proves.

---

## 1. The protocol landscape, as specified

Ordered by layer, because the layers are the story: each one deliberately leaves the layer above to somebody else.

| Protocol | Layer | Steward | Current spec | Defines about identity | Defines about authorization |
|---|---|---|---|---|---|
| **MCP** | agent ↔ tool/data | Agentic AI Foundation (donated by Anthropic) | revision `2026-07-28` | OAuth 2.1 client identity; no agent identity of its own | OAuth 2.1 resource-server model, **OPTIONAL** |
| **A2A** | agent ↔ agent | AAIF (Google → Linux Foundation → AAIF) | code `v1.0.1` (2026-05-28); published spec text is `1.0.0` at `/v1.0.0/` | Agent Card + optional JWS signature | "implementation-specific" (§7.5) |
| **AP2** | payments (A2A extension) | Google + partners, standardizing in FIDO WGs | A2A extension, `v0.1`-era | user credential or trusted agent provider | SD-JWT **Mandates** (Open/Closed) |
| **ANP** | identity-first agent network | open-source project; no foundation named on its spec site (observed 2026-10-28) | specs 1.x + `did:wba` | W3C DID (`did:wba`), DID-bound agent description | DID-auth then bearer token |
| **AGNTCY** | discovery / messaging / schema | Linux Foundation | dir, SLIM, OASF, Agent Connect Protocol | OASF records in a federated directory | delegated to A2A/MCP |
| **x402** | payments over HTTP | x402 Foundation (Coinbase origin) | spec v2 | wallet keys only | payment authorization, not agent authority |

Primary URLs: A2A — https://a2a-protocol.org/v1.0.0/specification · MCP — https://modelcontextprotocol.io/specification/versioning and https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization · AP2 — https://google-agentic-commerce.github.io/AP2/ap2/specification · ANP — https://agentnetworkprotocol.com/en/specs/ · AGNTCY — https://docs.agntcy.org/ · x402 — https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md

**Governance consolidated in 2026.** A2A was launched by Google in April 2025, donated to the Linux Foundation in June 2025 alongside AWS, Cisco, Microsoft, Salesforce, SAP and ServiceNow (https://linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents), and moved into the Agentic AI Foundation as a hosted project on 2026-08-17 (https://aaif.io/blog/a2a-joins-aaif). IBM's Agent Communication Protocol merged into A2A in August 2025 (same AAIF post). AAIF now hosts MCP, goose, AGENTS.md, agentgateway and A2A; it reported 247 member organizations as of 2026-08-13 (https://linuxfoundation.org/press/agentic-ai-foundation-welcomes-57-new-members-gaining-major-financial-services-players-and-apac-leaders). A2A v1.0.0 shipped 2026-03-12 and v1.0.1 on 2026-05-28 (GitHub releases, `a2aproject/A2A`).

**Two naming traps worth recording.** (a) IBM's *Agent Communication Protocol* (ACP) and Cisco/AGNTCY's *Agent Connect Protocol* (ACP) are different things; only the former merged into A2A. (b) AP2 is not a standalone wire protocol — it is an extension profile that rides on A2A (and, per its own docs, UCP). UCP itself (ucp.dev) was not examined here — **UNVERIFIED**.

Adoption claims in the AAIF post (150+ organizations; Huawei shipping A2A between Celia and in-app agents on HarmonyOS; Tencent WeChat integrating; Google Cloud, Azure AI Foundry and AWS Bedrock AgentCore hosting A2A endpoints) are the foundation's own claims, not independently measured. Treat as vendor-reported.

---

## 2. What A2A actually specifies about trust — and where it stops

Section names below are the real ones in the v1.0 specification; this matters because the prose is more careful than the marketing.

### 2.1 The security chapter is six sections, none of which is a delegation format

§7 *Authentication and Authorization* contains §7.1 Protocol Security, §7.2 Server Identity Verification, §7.3 Client Authentication Process, §7.4 Server Authentication Responsibilities, §7.5 Server Authorization Responsibilities, §7.6 In-Task Authorization.

§7.5 is one paragraph and it is the crux:

> "Once authenticated, the A2A Server authorizes requests based on the authenticated identity and its own policies. Authorization logic is implementation-specific and MAY consider: Specific skills requested / Actions attempted within tasks / Data access policies / OAuth scopes (if applicable)."

§13.1 *Data Access and Authorization Scoping* repeats it normatively: "Authorization boundaries are defined by each agent's authorization model, not prescribed by the protocol." §4.5 *Security Objects* defines exactly five scheme shapes — `apiKeySecurityScheme`, `httpAuthSecurityScheme`, `oauth2SecurityScheme`, `openIdConnectSecurityScheme`, `mtlsSecurityScheme` — all borrowed from the OpenAPI 3.2 Security Scheme Object. There is no `signedMandate` scheme, no `capability` scheme, no `proof` scheme.

So: **A2A standardizes who you are talking to and over what, and hands authority entirely to the server's private policy.** That is a defensible design choice for a messaging protocol. It is also why no two A2A deployments agree on what "this agent may do this" means.

### 2.2 Delegation exists only as a liveness fallback

§7.6.2 *In-Task Authorization Client Responsibilities* is the only place A2A talks about chains, and it is describing a **deadlock-avoidance pattern**, not an attenuation rule:

> "If the client is itself an A2A agent actively processing a Task, the client may further delegate the authorization request to its client by transitioning its own Task to `TASK_STATE_AUTH_REQUIRED`. … This enables forming a chain of Tasks in `TASK_STATE_AUTH_REQUIRED`."

Read carefully: the "chain" is a chain of *pending authorization requests* being bounced back up toward a human. Nothing about who may attenuate what, no scope algebra, no depth limit, no binding of hop *n* to hop *n−1*. Compare that with the academic treatments in §3.2, which all define attenuation as a partial order on capability sets — A2A defines nothing.

### 2.3 The Agent Card is a claim, not an attestation

§8.1: "A2A Servers MUST make an Agent Card available. The Agent Card is a JSON document that describes the server's identity, capabilities, skills, service endpoint URL, and how clients should authenticate." The field table in §4.4.1 describes `skills` as: "Skills represent the abilities of an agent. It is **largely a descriptive concept** but represents a more focused set of behaviors that the agent is likely to succeed at."

Signed cards arrived in v1.0 but are **optional** — §8.4: "Agent Cards **MAY** be digitally signed using JSON Web Signature (JWS) as defined in RFC 7515". §8.4.1 fixes the canonicalization (JCS / RFC 8785) and §8.4.2 the signature format, so the crypto is specified properly. What is *not* specified is the trust anchor: "Clients MAY maintain a trusted key store for known agent providers. Expired or revoked keys MUST NOT be used for verification. Multiple signatures MAY be present to support key rotation."

Three consequences:
1. A signed card proves *"the holder of key K signed this JSON"*. Whether K belongs to the organization in the `provider` field is out-of-band, per-client folklore. A verifier with no key store learns nothing.
2. A signature certifies the *description*, not the *behaviour*. Nothing binds the `skills` array to what the process will actually do when invoked. §1.2 *Guiding Principles* makes this explicit as a feature: "**Opaque Execution:** Agents collaborate based on declared capabilities and exchanged information, without needing to share their internal thoughts, plans, or tool implementations."
3. Key revocation is the only revocation A2A has. A grep of the 182 KB rendered specification text for `revok` returns exactly one hit, and it is about keys, not authority. `expir` returns four, all about expired tokens or purged tasks. There is no notion of a delegation that can be withdrawn, and no epoch or accumulator with which a verifier could check freshness (grep, 2026-10-28).

### 2.4 The extension system is the intended insertion point

Extensions are how A2A is meant to grow security layers without forking the core: "Extensions allow for extending the A2A protocol with new data, requirements, RPC methods, and state machines. Agents declare their support for specific extensions in their Agent Card … Extensions are identified by a URI and defined by their own specification. **Anyone is able to define, publish, and implement an extension.**" (https://a2a-protocol.org/latest/topics/extensions/)

Official extensions use the `https://a2a-protocol.org/extensions/` URI prefix; experimental ones use `experimental-ext-` repos. §4.6 defines the `AgentExtension` object carried in `capabilities.extensions`. This is the sanctioned, standards-body-blessed place to put a proof-carrying delegation layer, and it is a governance process, not a fork.

### 2.5 MCP says less, on purpose

MCP's authorization chapter is explicitly optional and delegates everything to OAuth: "Authorization is **OPTIONAL** for MCP implementations … Authorization servers **MUST** implement OAuth 2.1", with RFC 9728 protected-resource metadata, RFC 8414 AS metadata, RFC 7591 dynamic client registration and RFC 8707 resource indicators. The normative sentence that matters for multi-agent work is the anti-passthrough rule: servers "**MUST** only accept tokens specifically intended for themselves and **MUST** reject tokens that do not include them in the audience claim."

MCP's own *Security Best Practices* document names the failure mode that agent chains make routine — the **Confused Deputy Problem** — for MCP proxy servers that front a third-party API with a static client ID while letting clients register dynamically, plus a separate **Token Passthrough** section describing the "confused deputy" outcome when a server forwards an unvalidated token downstream. Both are documented as attack patterns with required mitigations; neither is solved structurally.

Current MCP protocol revision is `2026-07-28` (https://modelcontextprotocol.io/specification/versioning), negotiated per-request via `io.modelcontextprotocol/protocolVersion` in `_meta` and the `MCP-Protocol-Version` header, with a mandatory `server/discover` RPC for up-front capability/identity discovery.

### 2.6 AP2 is the most advanced authorization layer shipped — and it shows the ceiling of signed disclosure

AP2 is the one protocol in the stack that takes agent authorization seriously as a first-class object. Its own framing is the strongest available statement of the problem:

> "When communication happens between two non-agentic Roles, standard web security is sufficient to ensure integrity. However, when either role is agentic, **then the Agent itself is a potential attacker**. As such, additional tamper-evident mechanisms are needed." (https://google-agentic-commerce.github.io/AP2/ap2/specification)

§*Agent Authorization* splits authorization into **Mandate Delegation** (user approves Mandate Content on a **Trusted Surface**, which is *required* to be non-agentic) and **Action Authorization** ("a Verifier challenges an Agent to provide proof that it is authorized to perform an action on behalf of a User. The Agent does so by presenting a relevant Mandate to the Verifier. Upon completion, the Verifier returns the Agent a Receipt."). Two trust models: **User Credential** (an external Issuer backs the Trusted Surface) or **Trusted Agent Provider** (the agent's vendor is the trusted party).

Mandates are of two types, each in two stages: **Checkout Mandate** (Open = constraints on what to buy; Closed = authorization for a finalized checkout) and **Payment Mandate** (Open = budget/instrument constraints; Closed = authorization for a specific amount). AP2 "specifies the use of **SD-JWTs** for securing the Payment and Checkout Mandates."

This is a genuinely good design and it is the closest thing in production to what we are building. Its ceiling is precisely the thing ZK fixes:

- **Verification requires disclosure.** "Verifiers of Mandates *always* receive a closed Payment and Checkout Mandate … Constraints in these Mandates allow the verifier to verify that the Checkout and Payment match the User's intent. **Only constraints relevant to the closed Mandates are shared with the verifier.**" So a merchant learns your budget cap, category restrictions and time window in order to check compliance with them. SD-JWT discloses *values*; it cannot prove `amount ≤ budget` without revealing both.
- **No revocation anywhere.** "revok" appears zero times in the AP2 specification text (grep, 2026-10-28). Revocation of a delegated authority is an exercise left to the implementer.

---

## 3. What the academic literature says

The literature is 12–18 months old and thin on citations (which is why none are reported), but it is unusually convergent. Grouped by the question it answers.

### 3.1 Identity: solved-ish, and not the bottleneck

- **AgentDID** (arXiv:2604.25189) — DIDs + VCs for self-managed, short-lived agent identities, with the sharp observation that IAM assumes "centralized enrollment, persistent identifiers, and stable execution contexts" and agents violate all three; adds verification of dynamic execution state ("whether their context and capabilities remain valid at interaction time").
- **AI Agents with Decentralized Identifiers and Verifiable Credentials** (arXiv:2511.02841) — trust establishment at the *onset* of an agent-to-agent dialogue, i.e. the exact A2A `Agent Card` moment.
- **Agent Name Service / ANS** (arXiv:2604.26997) — DNS-analogue trust layer in Kubernetes; the paper is candid that its sub-10 ms figures come from "a demo research environment (3-node cluster, 50-agent workflow simulation)" and are "proof-of-concept evidence rather than production certification." Good model for how to scope claims.
- **ANP**'s `did:wba` is the spec-side counterpart: a `did:web` derivative tuned for agent handshakes, where the client puts its DID + signature in the first HTTP header and gets a bearer token back (https://agentnetworkprotocol.com/en/specs/03-did-wba-method-specification/).

Conclusion the literature keeps reaching: identity is necessary and *insufficient*, because it answers "who" and not "what were they allowed to do".

### 3.2 Delegation and attenuation: where the real design work is

- **Authenticated Delegation and Authorized AI Agents** (arXiv:2501.09674) — the canonical framing: delegate with restriction, keep "clear chains of accountability", extend OAuth 2.0 / OIDC with agent-specific credentials, and translate natural-language permissions into auditable access-control configs. This is the paper A2A-adjacent work builds on.
- **InterSAGE** (arXiv:2608.13030) — the most direct competitor in spirit. Four layers (Persistent Identity, Discovery, Trust Negotiation, Accountability) and four primitives: Agent Identity Cards binding "developer, code package, operator, and deployment context"; DID-bound VC capability manifests; "trust negotiation combining **monotonic capability attenuation** with two-tier access control"; and "kernel-mediated cryptographic audit trails that bind usage, delegation, and execution traces to agent identity without a consensus ledger." It explicitly "complements MCP, A2A, ANP, and AG-UI". Its opening claim is the cleanest statement of the gap: existing protocols "increasingly define how agents exchange messages, but not how an agent proves its identity, authorization, advertised capabilities, or accountability after delegation."
- **AIP / Invocation-Bound Capability Tokens** (arXiv:2603.24775) — the most implementation-complete: "IBCTs, a primitive that fuses identity, attenuated authorization, and provenance binding into a single append-only token chain", compact mode = signed JWT, chained mode = **Biscuit token with Datalog policies**. Reports 0.049 ms verification in Rust / 0.189 ms Python, 0.22 ms overhead over no-auth in MCP-over-HTTP, 2.35 ms added to a Gemini 2.5 Flash multi-agent deployment, and 100% rejection across 600 adversarial attempts. Its headline survey claim — "AI agents increasingly call tools via MCP and delegate to other agents via A2A, **yet neither protocol verifies agent identity**. A scan of approximately 2,000 MCP servers found all lacked authentication" — is the sentence our report should quote and, where possible, independently check.
- **Crypto-bound identity-verified capability tokens** (arXiv:2609.30824) — capability-based security over DID/VC and an OAuth Agent Authorization Profile, with the property that "Services can validate that the delegation chain only involves scope attenuation before acting on any given token", and the enforcement module lives "outside the language model's context window".
- **Digital Identity for Agentic Systems** (arXiv:2605.11487) — a portable authorization model built on "issuer-authored authorization payloads, **typed constraint algebra**, decision-consistent evaluation semantics, **delegation attenuation**, governed semantic resolution, fail-closed processing, and pre-flight discovery", deliberately separating credential container / payload semantics / enforcement engine so JWT, VC, OAuth RAR or policy-engine bindings "preserve a common authorization meaning across trust boundaries." This is the closest thing in the literature to a spec for the object we need to commit to.
- **Overlaying Governance** (arXiv:2606.03518) — compositional authorization for "recursive delegation, contextual boundaries, and dynamic scoping", arguing IAM's "fixed principals, explicit requests, and static scopes" cannot express agency.
- **DelegateGuard** (arXiv:2610.16005) — purpose-bound attenuable capabilities over "purpose, labels, operations, sinks, and delegation depth", with **revocation cascading through the delegation graph**, a trace-level safety invariant, and the important negative result: "Proposition 1 characterizes exactly where attenuation-based authorization suffices." 517,401 Enron emails as a corpus; microsecond per-decision overhead. If we want a serious revocation story, this is the state of the art to beat or adopt.

### 3.3 Empirical gap analyses: the strongest evidence that the gap is real

- **Delegation Without Trust** (arXiv:2609.00267) — the single most useful paper for our positioning. Its standard is the right one: "agent security must be evaluated under an **untrusted-model assumption**: a correct system is one in which a fully prompt-injected agent still cannot exceed the authority explicitly delegated to it." Contributions: a threat model of four adversaries (**confused deputy, token theft and replay, prompt-injection privilege escalation, compromised sub-agents**), eight derived security requirements, and an evaluation showing "a default agent runtime modeling common practice (broad bearer credentials, authorization gated inside the model) **fails all four threats**", and that "across four widely used frameworks — LangGraph, CrewAI, AutoGen, and the Model Context Protocol (MCP) authorization model — three provide no built-in confinement and one only partial; **no existing standard alone covers the requirement set**."
- **Authorization Architectures for Tool-Using AI Agents** (arXiv:2609.15906) — a review organized around a principal hierarchy (human user, operator/deployer, orchestrator agent, sub-agent, tool endpoint) and five layers: credential lifecycle; "delegation and scope propagation across multi-hop chains"; "runtime enforcement and just-in-time authorization at policy enforcement points (PEPs)"; audit; and the decision point itself. Its requirement triad is a good acceptance test for anything we build: every consequential action "traceable to a human principal, bounded by what that human actually delegated, and **contestable after the fact**."

### 3.4 Attestation of the runtime, not just the identity

- **Hardware-rooted attestation for AI-agent evidence** (arXiv:2608.00801) — defines an **action evidence package (AEP)**: "a signed, append-only record of what an AI agent did, who or what authorised the action, and what the outcome was", and argues such software attestation "is necessary but not sufficient" — when the verifier's question shifts from *what* to *whether the runtime was honest*, you need IETF RATS-style hardware roots. This is the strongest academic statement of the limit that a software-only proof hits.
- **D-MUTRA** (arXiv:2608.01938) — DLT-based mutual remote attestation between agents, motivated by "a compromised agent may execute modified software while appearing trustworthy."
- InterSAGE's audit layer and DelegateGuard's reference monitor are the two software-only designs that try to avoid hardware roots, both by mediating execution through a component outside the LLM.

### 3.5 Accountability vs. privacy: the tension nobody has resolved

- **Accountable yet Anonymous AI Agents** (arXiv:2607.23207) — documents that agent-identity infrastructure "has converged, in industry practice and research proposals alike, on a single resolution of the tension between accountability and privacy: **make every agent identifiable**", and analyses a national system (China, Q3 2026 launch) built on "split-knowledge binding" instead. This is the paper to cite against any design that assumes identifiability is the only route to accountability.
- **No One to Blame** (arXiv:2608.12104) — argues some configurations are *constitutively* unaccountable, i.e. not fixable by better standards. Useful as an honest bound on what any protocol (including ours) can promise.
- **Holding Agents Accountable with Verifiable Agent Insurance** (arXiv:2610.18230, per report 03) — the economic-recovery route rather than the prevention route.

### 3.6 What is *proven* vs. what is merely *specified*

Worth stating plainly, because the two get conflated in this space:

| Claim | Status |
|---|---|
| A2A `v1.0` defines 6 core operations, 3 bindings, an Agent Card with optional JWS | **Specified** (a2a-protocol.org/v1.0.0) |
| AP2 mandates are SD-JWTs with Open/Closed stages | **Specified** (AP2 spec) |
| MCP authorization is OAuth 2.1-based and optional | **Specified** (MCP authorization chapter) |
| Biscuit/Datalog chains attenuate and verify in 0.049 ms | **Implemented + measured**, single paper (2603.24775) |
| Four major frameworks fail to confine a prompt-injected agent | **Measured** on the authors' own default runtime + framework models (2609.00267) |
| ZK policy proofs are feasible at agent latency | **Measured, but with a wide spread** — see §4.4 |
| Signed agent cards establish organizational trust | **Not shown.** Spec leaves the key store out of scope (§8.4) |

---

## 4. Where zero-knowledge proofs add a guarantee no existing protocol provides

Three gaps, each stated as *what the spec says* → *what a paper shows is missing* → *what a proof adds*. Then the honest counter-case.

### Gap 1 — Nothing binds the *authorization* to the *executed action*

**What the specs do.** Every protocol in the stack binds a principal to a *permission to act*: A2A authenticates the caller and lets the server's private policy decide (§7.5, §13.1); AP2 binds a user to a Mandate and a Mandate to a checkout; MCP binds a client to an audience-restricted token. None of them produce evidence about *what was actually done*.

**What the literature shows.** This is the gap 2609.15906 names as "the authorization decision point itself, the moment a tool invocation occurs", and the one 2607.21325 formalizes: it "identifies and formalizes the structural separation among **identity binding, authorization-request binding, and runtime execution binding** as a central open problem." InterSAGE closes it with a kernel-mediated audit trail — which works only if you trust the kernel. 2608.00801 shows the software-only version is insufficient without hardware roots.

**What a proof adds.** A receipt: a public commitment to `(policy_commitment, action_class, timestamp, nonce)` plus a proof that *there exist* private `(action trace, delegation chain, signatures)` such that the trace is explainable by the policy inside the delegation. The verifier learns that the action was inside the policy without learning the action, and — critically — without having to trust the agent's host, which is the exact property InterSAGE and 2608.00801 both concede their designs do not have.

**Anchor quote for why this is not already solved:** AP2's own admission that "the Agent itself is a potential attacker", combined with its requirement that the agent *itself* assemble the Mandate Content. The party that must be constrained is the party constructing the evidence.

### Gap 2 — Disclosure is field-granular, never predicate-granular

**What the specs do.** AP2's SD-JWTs disclose selected *fields*. Its own words: "Only constraints relevant to the closed Mandates are shared with the verifier." So the merchant, to check that your purchase is inside your budget, receives your budget. A2A's skills are strings in a signed JSON document; a signed card's guarantee stops at "key K signed this text."

**What the literature shows.** 2608.30083 makes the general case and then hits the wall: agents either transmit raw data to a peer or "accept that peer's natural-language self-report that a value complies with policy. The first over-shares; the second is unverifiable." Its fix is a proof of a governance-defined predicate over private data, and the sentence that should shape our whole design is: "**because no interoperability protocol can carry such a proof, we propose a slot and implement it on both MCP and Agent2Agent from one endpoint.**" Someone had to invent the slot. A2A §4.6 and the `https://a2a-protocol.org/extensions/` namespace is the standards-sanctioned place to define it properly.

**What a proof adds.** Predicate-only compliance. `amount ≤ limit` with neither value revealed; `delegation depth ≤ k` without the identities of the intermediate hops; `action ∈ allowed_set` without the action. And for chains specifically, an **attenuation proof**: prove that a chain of *k* signed links exists from a root policy commitment to a leaf capability commitment with monotone narrowing at every hop, revealing only root, leaf, depth and nonce. Biscuit/Datalog (2603.24775, 2609.30824) gives the verifier the whole chain and its policies; the proof gives the verifier the *conclusion*.

### Gap 3 — No revocation, and accountability that requires doxxing the human

**What the specs do.** A2A defines key revocation only ("Expired or revoked keys MUST NOT be used for verification"). AP2 has no revocation concept at all — `revok` returns zero hits in the AP2 specification text (grep, 2026-10-28). Delegation expiry is not enforced by any of them.

**What the literature shows.** DelegateGuard is the only work here that treats revocation as structural — "revocation cascades through the delegation graph" — and it does so inside a reference monitor, i.e. again requiring a trusted mediator. 2607.23207 shows the field's default answer to accountability is "make every agent identifiable", and that this is a *choice* with a privacy cost, not a necessity.

**What a proof adds.** Two distinct things:
1. **Non-revocation as a public input.** Commit to an accumulator/epoch root; the proof shows the delegation is in the set (or absent from the revoked set) at epoch *t*, with no online call to the issuer and no disclosure of which delegation it is. This is a standard ZK primitive applied to an object no agent protocol currently has.
2. **Accountability without identifiability.** Prove "I act under a delegation whose root was issued by *some* principal that passed attestation *A*" while revealing neither the principal nor the delegation. 2607.23207's split-knowledge design is the non-ZK version of this idea; a proof makes it composable with every verifier that speaks A2A.

### 4.4 The honest counter-case, with numbers

ZK is not free and the literature contains a real argument against it at agent latency. All figures below are as reported by their authors.

| System | What is proven | Prove | Verify | Proof size |
|---|---|---|---|---|
| zkLLM (as cited by 2603.10060) | LLM inference | ~180 s/query | — | — |
| NiyamAI (2608.07167) | policy evaluation over a committed Intent Contract (zkSNARK) | **1.7 s/action** | **51 ms** | 18.6 KB |
| ZK predicate gateway (2608.30083) | 32-bit threshold predicate (Bulletproofs) | **6.2 ms** | **1.0 ms** | 608 B |
| AIP (2603.24775) | *no ZK* — signed Datalog chain | n/a | **0.049 ms** | JWT/Biscuit |
| **zkagent (project baseline)** | policy satisfaction over private actions (Groth16, BN254, 3,333 constraints, 15 public inputs) | not captured in this slice | **50–100 ms** | **128 B** |

Read the table as a design rule rather than a scoreboard:

- **Proving the model is dead** (180 s/query) and the Tool Receipts paper (2603.10060) is right to reject it. Its measured alternative — HMAC-signed tool receipts, 94.2% detection of fabricated tool references at <15 ms — is the correct baseline for *hallucination* detection, which is a different problem.
- **Proving the policy decision is alive.** 1.0 ms verify (608 B) and 51 ms verify (18.6 KB) bracket what is achievable. Our 128-byte proof verifying in 50–100 ms sits inside that band. NiyamAI's 1.7 s *prove* is the real cost, and it is a per-action cost — which is why the prover has to be cheap enough to run inline, or the proof has to be produced once per *task* rather than once per tool call.
- **Signature-only schemes will always be 3–4 orders of magnitude cheaper to verify.** AIP's 0.049 ms is not beatable and should not be the competition. The argument for ZK is never speed; it is *what the verifier learns* — that a verifier who trusts neither the agent, nor its host, nor the issuer's honesty about attenuation, still gets a sound answer.
- **The strongest published objection** is 2603.10060's framing that ZK is impractical for interactive agents. It is correct about inference and does not apply to a 3,333-constraint circuit. Conceding the inference case explicitly, in the paper and in the README, is cheaper than being accused of ignoring it.

### 4.5 Where this leaves the citations

Semantic Scholar was rate-limited for almost the whole session (HTTP 429). The only two counts retrieved: arXiv:2607.21325 → 1 citation, arXiv:2609.30824 → 0 citations (2026-10-28). Directionally: this literature is too new for citation counts to be informative, and no argument here should rest on impact metrics.

---

## 5. Concrete implications for zkagent

Ordered by cost-to-implement, because the first three are cheap and the fourth is the actual research.

1. **Ship the chain as an A2A extension, not as a fork.** A2A explicitly invites it ("Anyone is able to define, publish, and implement an extension", URI namespace `https://a2a-protocol.org/extensions/{name}/v1`), and §4.6's `AgentExtension` is already carried in `capabilities.extensions`. Concretely: an extension whose `params` carry `{root_policy_commitment, depth, revocation_epoch, verifier_key}` and whose proof travels as a `DataPart` on the task. This costs one JSON schema and buys interoperability with every A2A implementation for free.
2. **Define the link relation explicitly.** Public inputs: `(root_commitment, child_commitment, depth, epoch_root, nonce, receipt_hash)`. Private: `(parent policy, child policy, both signatures, revocation witness)`. This is the object 2607.21325 calls "runtime execution binding" and 2605.11487 calls "delegation attenuation"; naming ours after theirs makes the comparison legible.
3. **Add an AP2 constraint type.** AP2's `Mandate Constraints` extension point says: "To define a new constraint, the following MUST be specified: A uniquely defined `type`. A Schema, including which fields are selectively disclosable. **The evaluation algorithm.**" A constraint type whose evaluation algorithm is "verify a Groth16 proof attached to this mandate" is a conforming AP2 extension and the cheapest possible route to relevance in agentic commerce.
4. **The research bet: prove the trace, not the model, and not the kernel.** Our 3,333-constraint circuit is the right shape — small enough to verify in 50–100 ms, expressive enough to cover caps/expiry/chain/allow-list. The spectrum between 1.0 ms predicates and 1.7 s policy proofs is where the delegation-link proof has to land.

**What we should not claim.** That signed mandates are broken (they are not — AP2's design is sound, it just discloses more than necessary). That attestation is useless (2608.00801 shows hardware roots are *necessary* for the runtime-honesty question). That ZK is fast (it is not; it is merely cheap enough for the decision, not the inference).

---

## 6. Open questions

1. Does the A2A extension governance process actually accept a security extension from outside the founding set, and on what timeline? Not tested here — **UNVERIFIED**.
2. Is there a ZK delegation-chain format already deployed in an A2A or MCP extension registry that this survey missed? Searched arXiv (keyword), not the extension registries comprehensively — **UNVERIFIED**.
3. How does UCP (ucp.dev) interact with AP2's role model, and does it define anything about agent authority independently? Not examined — **UNVERIFIED**.
4. What is the real cost of a non-revocation proof at agent latency? No paper found that measures it in this setting — **UNVERIFIED / plausible gap**.
5. Whether A2A's `TASK_STATE_AUTH_REQUIRED` bounce chain has been exploited in the wild as a privilege-laundering path (each hop re-requesting authority upward with a widened ask). No paper found; the spec's silence on attenuation means nothing prevents it — **UNVERIFIED**.

---

## Sources

**Specifications (primary, all fetched 2026-10-28)**
- A2A v1.0 specification — https://a2a-protocol.org/v1.0.0/specification
- A2A releases (v1.0.0 2026-03-12, v1.0.1 2026-05-28) — https://github.com/a2aproject/A2A/releases
- A2A extensions & governance — https://a2a-protocol.org/latest/topics/extensions/
- MCP versioning (current `2026-07-28`) — https://modelcontextprotocol.io/specification/versioning
- MCP authorization — https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- MCP security best practices (confused deputy, token passthrough) — https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- AP2 specification — https://google-agentic-commerce.github.io/AP2/ap2/specification
- AP2 agent authorization framework — https://google-agentic-commerce.github.io/AP2/ap2/agent_authorization
- AP2 overview / A2A extension status — https://google-agentic-commerce.github.io/AP2
- ANP specifications index — https://agentnetworkprotocol.com/en/specs/
- ANP `did:wba` method — https://agentnetworkprotocol.com/en/specs/03-did-wba-method-specification/
- AGNTCY stack (directory, SLIM, OASF, ACP) — https://docs.agntcy.org/ and https://dir.agntcy.org/
- x402 specification v2 — https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md

**Governance**
- Linux Foundation launches A2A project (2025-06-23) — https://linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents
- A2A joins AAIF (2026-08-17) — https://aaif.io/blog/a2a-joins-aaif
- AAIF membership growth (2026-08-13) — https://linuxfoundation.org/press/agentic-ai-foundation-welcomes-57-new-members-gaining-major-financial-services-players-and-apac-leaders
- OpenAI co-founds AAIF, donates AGENTS.md — https://openai.com/index/agentic-ai-foundation

**Papers**
- 2501.09674 Authenticated Delegation and Authorized AI Agents — https://arxiv.org/abs/2501.09674
- 2511.02841 AI Agents with DIDs and VCs — https://arxiv.org/abs/2511.02841
- 2603.10060 Tool Receipts, Not Zero-Knowledge Proofs — https://arxiv.org/abs/2603.10060
- 2603.24775 AIP: Agent Identity Protocol (IBCT) — https://arxiv.org/abs/2603.24775
- 2604.25189 AgentDID — https://arxiv.org/abs/2604.25189
- 2604.26997 Agent Name Service — https://arxiv.org/abs/2604.26997
- 2605.11487 Digital Identity for Agentic Systems — https://arxiv.org/abs/2605.11487
- 2606.03518 Overlaying Governance — https://arxiv.org/abs/2606.03518
- 2606.19135 A Technical Taxonomy of LLM Agent Communication Protocols — https://arxiv.org/abs/2606.19135
- 2607.21325 Cryptographically verifiable authorization for autonomous AI agents — https://arxiv.org/abs/2607.21325
- 2607.23207 Accountable yet Anonymous AI Agents — https://arxiv.org/abs/2607.23207
- 2608.00801 Hardware-rooted attestation for AI-agent evidence (RATS + AEP) — https://arxiv.org/abs/2608.00801
- 2608.01938 D-MUTRA — https://arxiv.org/abs/2608.01938
- 2608.07167 NiyamAI (intent-bound ZK guardrails) — https://arxiv.org/abs/2608.07167
- 2608.12104 No One to Blame — https://arxiv.org/abs/2608.12104
- 2608.13030 InterSAGE — https://arxiv.org/abs/2608.13030
- 2608.30083 Zero-Knowledge Predicate Proofs Between AI Agents — https://arxiv.org/abs/2608.30083
- 2609.00267 Delegation Without Trust — https://arxiv.org/abs/2609.00267
- 2609.15906 Authorization Architectures for Tool-Using AI Agents — https://arxiv.org/abs/2609.15906
- 2609.30824 Crypto-bound identity-verified capability tokens — https://arxiv.org/abs/2609.30824
- 2610.16005 DelegateGuard — https://arxiv.org/abs/2610.16005
- 2610.23078 Cryptographically Secure Agent-to-Agent Communication — https://arxiv.org/abs/2610.23078
- 2610.18230 Holding Agents Accountable with Verifiable Agent Insurance — https://arxiv.org/abs/2610.18230 (metadata taken from report 03, not re-fetched here)
