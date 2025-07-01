#!/usr/bin/env python3
"""Script to test uploading size analysis files to Sentry using the complete chunking flow."""

import json
import logging
import os
import sys

import click

sys.path.insert(0, "src")
from launchpad.sentry_client import SentryClient


@click.command()
@click.option(
    "--base-url", default="http://localhost:8000", help="Base URL for Sentry API"
)
@click.option("--org", default="sentry", help="Organization slug")
@click.option("--project", default="internal", help="Project slug")
@click.option("--artifact-id", default="1", help="Artifact ID to upload analysis for")
@click.option("--file-path", default="README.md", help="Path to file to upload")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def main(
    base_url: str,
    org: str,
    project: str,
    artifact_id: str,
    file_path: str,
    verbose: bool,
) -> None:
    """Test uploading size analysis files to Sentry using the complete chunking flow."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Verify file exists
    if not os.path.exists(file_path):
        click.echo(f"❌ File not found: {file_path}")
        sys.exit(1)

    file_size = os.path.getsize(file_path)

    try:
        click.echo(
            f"Testing size analysis upload: {org}/{project}/artifacts/{artifact_id}"
        )
        click.echo(f"📁 File: {file_path} ({file_size:,} bytes)")

        client = SentryClient(base_url=base_url)

        click.echo("🔄 Starting size analysis upload...")
        click.echo("   📊 Calculating checksums...")
        click.echo("   🚀 Calling assemble endpoint...")

        response = client.upload_size_analysis_file(
            org, project, artifact_id, file_path
        )

        if "error" in response:
            click.echo(
                f"❌ Failed: {response['error']} (Status: {response.get('status_code', 'Unknown')})"
            )
            if "message" in response:
                click.echo(f"   Message: {response['message']}")
            sys.exit(1)

        click.echo("✅ Size analysis upload successful!")

        # Show relevant response data
        if "checksum" in response:
            click.echo(f"📄 File checksum: {response['checksum']}")
        if "chunks" in response:
            click.echo(f"🧩 Chunks processed: {len(response['chunks'])} chunk(s)")
        if "state" in response:
            click.echo(f"📊 Analysis state: {response['state']}")

        if verbose:
            click.echo(f"📄 Full response: {json.dumps(response, indent=2)}")

    except FileNotFoundError as e:
        click.echo(f"❌ File error: {e}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        if verbose:
            import traceback

            click.echo(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
