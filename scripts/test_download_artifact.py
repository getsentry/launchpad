#!/usr/bin/env python3
"""Script to test downloading artifacts from Sentry using the internal endpoint."""

import json
import logging
import os
import sys
import time

import click

sys.path.insert(0, "src")
from launchpad.sentry_client import SentryClient


@click.command()
@click.option(
    "--base-url", default="http://localhost:8000", help="Base URL for Sentry API"
)
@click.option("--org", default="sentry", help="Organization slug")
@click.option("--project", default="internal", help="Project slug")
@click.option("--artifact-id", default="1", help="Artifact ID to download")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def main(
    base_url: str, org: str, project: str, artifact_id: str, verbose: bool
) -> None:
    """Test downloading artifacts from Sentry using the internal endpoint."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    try:
        click.echo(f"Testing download: {org}/{project}/artifacts/{artifact_id}")

        client = SentryClient(base_url=base_url)
        start_time = time.time()

        response = client.download_artifact(org, project, artifact_id)
        duration = time.time() - start_time

        if "error" in response:
            click.echo(
                f"❌ Failed: {response['error']} (Status: {response.get('status_code', 'Unknown')})"
            )
            sys.exit(1)

        file_content = response.get("file_content", b"")
        file_size = len(file_content)

        if not file_content:
            click.echo("❌ No file content received")
            sys.exit(1)

        # Save file to disk
        timestamp = int(time.time())
        file_ext = ".zip" if file_content.startswith(b"PK") else ".bin"
        filename = (
            f"preprod_artifact_{org}_{project}_{artifact_id}_{timestamp}{file_ext}"
        )
        file_path = os.path.join(os.getcwd(), filename)

        with open(file_path, "wb") as f:
            f.write(file_content)

        # Verify and report
        disk_size = os.path.getsize(file_path)
        integrity_ok = file_size == disk_size

        click.echo(f"✅ Downloaded {file_size:,} bytes in {duration:.2f}s")
        click.echo(f"💾 Saved to: {file_path}")
        click.echo(
            f"{'✅' if integrity_ok else '⚠️ '} File integrity: {'OK' if integrity_ok else 'MISMATCH'}"
        )

        if verbose:
            click.echo(
                f"📄 Headers: {json.dumps(response.get('headers', {}), indent=2)}"
            )

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        if verbose:
            import traceback

            click.echo(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
