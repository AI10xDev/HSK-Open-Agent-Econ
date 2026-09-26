"""Mock CLI for the HSK-signed harness store.

This is a *mock*: it performs no signing, opens no socket, and moves no HSK. It
exists to pin down the shape of the ``--store`` flow before the real thing is
built, so the prompt/UX can be argued about against something runnable.

    python mock_store.py --store                  # sign -> banner -> list -> prompt
    python mock_store.py --store --balance 5.0    # enough HSK to fund anything
    python mock_store.py --store --no-input       # print the list, select nothing
    echo 1 | python mock_store.py --store         # piped stdin instead of a tty

The flow, in order:

  1. ``--store`` is present                       (the gate)
  2. a body of text: "HSK Signed - and here are the available harnesses"
  3. the list of harnesses
  4. ``input("Select Harness - fund iff possible")``

Step 4's "fund iff possible" is read in its strict logical sense: fund the
selection *exactly when* funding is possible, and otherwise say why not. A mock
that funds first and apologises afterwards would be the weaker claim. See
``funding_possible``.

Stdlib only -- deliberately importable without the venv, so the UX can be
demoed on a machine that has no HSKChain RPC configured.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

BANNER = "HSK Signed - and here are the available harnesses"
PROMPT = "Select Harness - fund iff possible"


@dataclass(frozen=True)
class Harness:
    """One sellable harness. ``cost_hsk`` is the mock price, in HSK."""

    key: str
    name: str
    blurb: str
    cost_hsk: float

    def matches(self, raw: str) -> bool:
        """True if ``raw`` names this harness -- by number, key, or name.

        Number and key are what a human types; the name match is the forgiving
        path, since the three display names differ only in case and word.
        """
        text = raw.strip().lower()
        if not text:
            return False
        if text.isdigit():
            return 1 <= int(text) <= len(HARNESSES) and HARNESSES[int(text) - 1] is self
        return text in {self.key, self.name.lower()}

    def affordable_with(self, balance: float) -> bool:
        return balance >= self.cost_hsk


# Ordered as displayed: the numbering in the prompt refers to this order.
HARNESSES: tuple[Harness, ...] = (
    Harness("email", "Email Harness", "reads and drafts mail, nothing else", 0.5),
    Harness("computer-use", "computer use harness", "drives a real desktop session", 2.0),
    Harness("spec-editor", "spec editor harness", "edits specs in place, reviewable diffs", 1.0),
)


def _mock_sign() -> str:
    """Stand in for the EIP-191 personal_sign handshake.

    Real signing needs a key and, on mainnet, an account with a footprint; the
    mock just reports that it would have. Returning the fake signer address lets
    the rest of the script treat the session as authenticated.
    """
    return "0x745a955AdA130f8556f1359fC3830ef77C638e8E"


def print_banner() -> None:
    """The body of text that comes before the list."""
    print()
    print(BANNER)
    print(f"  (mock) signed by {_mock_sign()} -- no key was used, no RPC was called")
    print()


def print_list() -> None:
    """The harness list, numbered so the prompt can take a digit."""
    print("Available harnesses:")
    for i, harness in enumerate(HARNESSES, start=1):
        print(f"  [{i}] {harness.name:<22} {harness.cost_hsk:>5.2f} HSK   {harness.blurb}")
    print(f"\n  Enter a number (1-{len(HARNESSES)}), a key, or the full name.")
    print("  Blank or 'q' quits without funding anything.")
    print()


def resolve(raw: str) -> Harness | None:
    """The harness the user named, or None if nothing matched."""
    for harness in HARNESSES:
        if harness.matches(raw):
            return harness
    return None


def funding_possible(harness: Harness, balance: float, faucet_available: bool) -> tuple[bool, str]:
    """Whether ``harness`` can be funded right now, and if not, why.

    The three ways funding is *not* possible, in the order worth reporting:

      1. no faucet on this network -- HSKChain mainnet has none, so the answer
         is structurally "no" and the balance never even gets consulted;
      2. free harness -- nothing to fund, so funding would be a no-op;
      3. balance short of the price.
    """
    if not faucet_available:
        return False, "this network has no faucet (mainnet has none), so there is nothing to fund from"
    if harness.cost_hsk == 0:
        return False, "harness is free -- no funding required"
    if not harness.affordable_with(balance):
        short = harness.cost_hsk - balance
        return False, f"balance {balance:.2f} HSK is {short:.2f} HSK short of {harness.cost_hsk:.2f}"
    return True, f"balance {balance:.2f} HSK covers {harness.cost_hsk:.2f} HSK"


def fund(harness: Harness, balance: float, faucet_available: bool) -> int:
    """Fund the selection iff funding is possible. Returns a process exit code.

    Both branches are normal outcomes, not errors: a refusal prints its reason
    and still exits 0, because "could not fund" is a legitimate answer to the
    question the prompt asked.
    """
    possible, why = funding_possible(harness, balance, faucet_available)
    print(f"\nSelected: {harness.name}")
    if not possible:
        print(f"  not funded -- {why}")
        return 0

    # Mock settlement: no drip is actually requested and no tx is broadcast.
    print(f"  funded -- {harness.cost_hsk:.2f} HSK (mock). {why}.")
    print(f"  remaining balance: {balance - harness.cost_hsk:.2f} HSK")
    return 0


def cmd_store(args: argparse.Namespace) -> int:
    """The ``--store`` flow: sign, banner, list, prompt, fund."""
    print_banner()
    print_list()

    if args.no_input:
        print("  --no-input: stopping before the prompt.")
        return 0

    try:
        raw = input(f"{PROMPT}: ")
    except EOFError:
        # Piped stdin with nothing left: treat as "user walked away", not a crash.
        print("\n  no input on stdin -- nothing selected, nothing funded.")
        return 0
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("\n  cancelled -- nothing funded.")
        return 130

    if raw.strip().lower() in {"q", "quit", "exit"}:
        print("  quit -- nothing funded.")
        return 0

    if not raw.strip():
        print("  nothing selected -- nothing funded.")
        return 0

    harness = resolve(raw)
    if harness is None:
        print(f"  '{raw.strip()}' is not one of the {len(HARNESSES)} harnesses -- nothing funded.")
        return 1

    return fund(harness, args.balance, not args.no_faucet)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mock_store.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--store",
        action="store_true",
        help="open the harness store (the flow this mock exists to demonstrate)",
    )
    parser.add_argument(
        "--balance",
        type=float,
        default=0.0,
        metavar="HSK",
        help="mock wallet balance, used to decide whether funding is possible",
    )
    parser.add_argument(
        "--no-faucet",
        action="store_true",
        help="pretend this network has no faucet, so funding is never possible",
    )
    parser.add_argument(
        "--no-input",
        action="store_true",
        help="print the list and stop before prompting (for tests)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.store:
        print("nothing to do: pass --store to open the harness store.")
        print("try: python mock_store.py --help")
        return 0
    return cmd_store(args)


if __name__ == "__main__":
    sys.exit(main())
