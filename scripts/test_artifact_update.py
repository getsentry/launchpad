#!/usr/bin/env python3
"""Script to test updating artifacts in Sentry using the internal endpoint."""

import json
import logging
import sys
from datetime import datetime

import click

sys.path.insert(0, "src")
from launchpad.sentry_client import SentryClient


@click.command()
@click.option(
    "--base-url", default="http://localhost:8000", help="Base URL for Sentry API"
)
@click.option("--org", default="sentry", help="Organization slug")
@click.option("--project", default="internal", help="Project slug")
@click.option("--artifact-id", default="1", help="Artifact ID to update")
@click.option("--artifact-type", type=int, help="Artifact type (0=APK, 1=IPA, 2=AAB)")
@click.option("--build-version", help="Build version string")
@click.option("--build-number", type=int, help="Build number")
@click.option("--error-message", help="Error message (sets state to FAILED)")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def main(
    base_url: str,
    org: str,
    project: str,
    artifact_id: str,
    artifact_type: int | None,
    build_version: str | None,
    build_number: int | None,
    error_message: str | None,
    verbose: bool,
) -> None:
    """Test updating artifacts in Sentry using the internal endpoint."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Build update data from provided options
    update_data = {}

    if artifact_type is not None:
        update_data["artifact_type"] = artifact_type
    if build_version:
        update_data["build_version"] = build_version
    if build_number is not None:
        update_data["build_number"] = build_number
    if error_message:
        update_data["error_message"] = error_message

    # Add a timestamp to show it was updated
    update_data["date_built"] = datetime.utcnow().isoformat() + "Z"

    if not update_data or update_data == {"date_built": update_data["date_built"]}:
        click.echo("❌ No update fields provided. Use --help to see available options.")
        sys.exit(1)

    try:
        click.echo(f"Testing update: {org}/{project}/artifacts/{artifact_id}")
        click.echo(f"Update data: {json.dumps(update_data, indent=2)}")

        client = SentryClient(base_url=base_url)
        response = client.update_artifact(org, project, artifact_id, update_data)

        if "error" in response:
            click.echo(
                f"❌ Failed: {response['error']} (Status: {response.get('status_code', 'Unknown')})"
            )
            if "message" in response:
                click.echo(f"   Message: {response['message']}")
            sys.exit(1)

        success = response.get("success", False)
        updated_fields = response.get("updated_fields", [])
        artifact_id_resp = response.get("artifact_id", "Unknown")

        if success:
            click.echo(f"✅ Successfully updated artifact {artifact_id_resp}")
            click.echo(
                f"📝 Updated fields: {', '.join(updated_fields) if updated_fields else 'none'}"
            )
        else:
            click.echo("⚠️  Update completed but success flag is False")

        if verbose:
            click.echo(f"📄 Full response: {json.dumps(response, indent=2)}")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        if verbose:
            import traceback

            click.echo(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
