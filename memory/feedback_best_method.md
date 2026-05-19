---
name: Always seek the best method
description: Never settle for "fine" or "good enough" — always find the state of the art approach
type: feedback
---

Always seek out the best method for anything. The state of the art. Never settle for "good enough" or "fine."

**Why:** Explicitly corrected when I said a linear scan was "fine" for in-flight lookup given small pool size — the right call was to use a HashMap for O(1) lookup regardless.

**How to apply:** When evaluating implementation choices, don't stop at "acceptable given constraints." Find the best approach unconditionally, then apply it.
