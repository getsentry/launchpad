#!/bin/bash

echo "Debug: GO_REVISION_LAUNCHPAD_REPO=${GO_REVISION_LAUNCHPAD_REPO}"

checks-googlecloud-check-cloudbuild \
  sentryio \
  launchpad \
  launchpad-main-trigger \
  "${GO_REVISION_LAUNCHPAD_REPO}" \
  main
