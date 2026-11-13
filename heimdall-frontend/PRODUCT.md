# Heimdall product brief

**What it is.** A dual-gateway firewall for language-model applications. Gateway 1 screens a prompt before a model reads it. Gateway 2 screens the answer before a person does. The console shows every layer's verdict, evidence and cost.

**Who it is for.** Engineers and researchers deciding whether a prompt-injection defence holds up. They are sceptical, technical, and want evidence before claims.

**What the interface must do.**

1. Let a visitor test the gate in the first minute (the scan bench on Home, then the Console).
2. Show measured results with their conditions and limits next to them.
3. Explain a verdict layer by layer, never as a single opaque score.
4. Fail in the open: every error says what broke, why, and the one action that fixes it.

**Voice.** Direct and exact. State what was measured and where it stops being evidence. Heimdall is a research prototype and says so.

**Never.** Invented statistics, stock security imagery, fear copy, or a claim of guaranteed protection.

**Pages.** Home, Console (`/chat`), Attack Lab (`/simulation`), Analytics, Immune, Research, About, Review queue, Policies, Debug.
