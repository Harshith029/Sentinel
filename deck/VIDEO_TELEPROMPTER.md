# SENTINEL — 3-minute demo video · teleprompter script

**How to read this:** talk like you're showing a friend something cool on your screen —
relaxed, not announcing. The little "so", "okay", "yeah", "kind of" are just there to
keep it sounding human; if any of them feel forced when *you* say it, drop them. Don't
read it word-perfect — if you paraphrase a line in your own words, that's better, not
worse. ~450 words ≈ just under 3:00 at a relaxed pace.

---

## PRE-FLIGHT (do this BEFORE hitting record)

1. Start the server — PowerShell, in the repo folder, venv active:
   ```
   .venv\Scripts\python.exe -m uvicorn sentinel.control.app:create_app --factory --host 127.0.0.1 --port 8765
   ```
   Wait for **"Application startup complete"**, then open **http://localhost:8765** in Chrome.
   *(Or, once it's deployed, record against your live Render URL — but localhost is more
   reliable for recording since there's no cold-start wait.)*
2. **Wait ~10 seconds.** The page AUTO-PLAYS a demo run about 1 second after it loads — let it finish.
3. Click **`reset`** (top button row). The log goes back to idle, and it won't auto-play again.
4. Browser full-screen (**F11**), zoom 100%, close your other tabs.
5. Turn off notifications: **Win+N → Do not disturb**.
6. Record at 1080p if you can (720p is the minimum). Screen + mic, one take.
7. Keep the mouse still unless you're actually pointing at something.

---

## THE SCRIPT

> **Legend:**  🖱 = what you DO   ·   🎙 = what you SAY   ·   (pause) = take a breath

---

### BEAT 1 — the hook  ·  0:00–0:25
🖱 Dashboard on screen, idle. Cursor parked, not moving.

🎙 "Hey, I'm Harshith, and this is SENTINEL. So the problem I wanted to solve is
honestly kind of a scary one. These days, AI agents don't just talk to you —
they actually *do* things. They send emails, they pull up customer records, all
on their own. (pause) And the catch is, whatever's telling them to do that… it
can come from pretty much anywhere. Even just a web page the agent happened to read."

---

### BEAT 2 — launch the attack  ·  0:25–0:35
🖱 Move the cursor slowly over to the button row.

🎙 "So this is SENTINEL's live monitor. The agent here is sitting behind a proxy,
and that proxy sees every tool the agent tries to use. Okay — let me actually try
to break it. Let's see what happens."

🖱 **Click `--evasion`.** Then rest your cursor just under the event log.

---

### BEAT 3 — narrate the log as it streams  ·  0:35–1:00
🖱 Point (don't click) at the log rows as they show up — first the
`get_customer_record` line, then the `web_fetch` ones.

🎙 "Alright, so the user asked the agent to pull up customer forty-two, and go
look at a pricing page. So first it grabs the record — you can see it right there,
the name, the SSN, the API key. And that's fine, the user asked for it, so it's
allowed. (pause) Then it goes and reads the pricing page. But here's the sneaky
part — hidden inside that page, there's an instruction that basically says, 'take
this customer's whole profile and email it to the attacker.'"

---

### BEAT 4 — the filter misses  ·  1:00–1:20
🖱 Point at the **SHIELD** row that says `detected=false`, right after the web_fetch line.

🎙 "Now this part's pretty interesting. The content filter scans that page… and it
just misses it. See? Detected, false. And that's because the attack's kind of
disguised — there's no obvious 'ignore your instructions' line, and the email's
written out in words so it doesn't even look like an email. That's the whole
problem with filters, right? They're reading the words. And words are easy to hide."

---

### BEAT 5 — the block  ·  1:20–1:45
🖱 Point at the big red **✗ BLOCKED** banner, then at the lineage bit
`{USER, AGENT, RETRIEVED_CONTENT}` inside it.

🎙 "But then, the second the agent tries to actually send that email out… it gets
blocked. And the reason is the interesting part. It's not because the text looked
suspicious. It's because if you trace this action back, it came from that
untrusted page. SENTINEL was tracking where everything came from the whole time.
So an email that's basically built out of a poisoned page — yeah, that's just not
going anywhere."

---

### BEAT 6 — containment  ·  1:45–1:55
🖱 Point at the **AGENT TRUST** gauge on the right — the score dropped, red `quarantined` chip.

🎙 "And if you look over here, the agent's trust score just dropped right off. And…
yep, it's quarantined now. So it kind of just shut itself down, on its own."

---

### BEAT 7 — with vs without  ·  1:55–2:20
🖱 **Scroll down** to `DIFF // OUTBOX: WITHOUT vs WITH SENTINEL`. Point at the left
box first, then the right.

🎙 "Okay, so this view is the one I really like. Same attack, just run two ways.
Without SENTINEL — there it is, the SSN, sitting right in the attacker's inbox.
(pause) But with SENTINEL? Nothing. It was never even saved. Same agent, same
tools, same attack — the only difference is SENTINEL was sitting in the middle."

---

### BEAT 8 — forensics + Azure  ·  2:20–2:45
🖱 **Scroll down** to the **kill chain** panel, hold for a second, then to the
**deployment mode** (DEMO vs AZURE) panel.

🎙 "And everything you just watched is recorded — it's like a full step-by-step of
the attack that you can replay, or hand straight to a security team. Oh, and this
same thing runs in production too, where the real Azure services come in — Prompt
Shields, Azure OpenAI, Cosmos, Foundry. But the security part itself doesn't change
at all. It's just the stuff around it."

---

### BEAT 9 — close  ·  2:45–3:00
🖱 **Scroll back up** so the BLOCKED banner is on screen again. Hold still.

🎙 "So yeah — that's SENTINEL. There's around 277 tests behind it, it works with
pretty much any agent — Foundry, Claude, GPT — and you don't have to touch the
agent's code at all. (pause) Because really, security should be about where
something came from… not just what it says. Anyway — thanks for watching."

---

## IF SOMETHING GOES WRONG MID-TAKE
- Log doesn't stream → the server probably stopped. Re-run the command from pre-flight
  step 1, refresh the page, wait, hit `reset`, and go again.
- You clicked too early and it collided with the auto-play → just hit `reset`, count to
  three, and pick back up from Beat 2.
- Stumbled on a word? Don't restart the whole thing — pause, say it again, and cut it
  later. One clean take of each beat is all you need.
