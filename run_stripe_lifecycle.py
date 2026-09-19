import argparse
import json
import os
from pathlib import Path

from cape_artifact.stripe_lifecycle import run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path(__file__).resolve().parent / "results" / "external_validation",
    )
    parser.add_argument("--i-accept-stripe-test-calls", action="store_true")
    args = parser.parse_args()

    if not args.i_accept_stripe_test_calls:
        parser.error(
            "this makes real calls to Stripe's test-mode API; re-run with --i-accept-stripe-test-calls"
        )

    secret_key = os.environ.get("STRIPE_SECRET_KEY")
    if not secret_key:
        parser.error("set STRIPE_SECRET_KEY (a sk_test_... key) as an environment variable")

    summary = run(secret_key, args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
