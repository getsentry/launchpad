#!/bin/bash

checks-googlecloud-check-cloudbuild \
  sentryio \
  launchpad \
  launchpad-main-trigger \
  "${GO_REVISION_LAUNCHPAD_REPO}" \
  main \
  --location=us-central1
