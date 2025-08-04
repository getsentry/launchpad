#!/bin/bash

checks-googlecloud-check-cloudbuild \
  sentryio \
  launchpad \
  launchpad-builder \
  "${GO_REVISION_LAUNCHPAD_REPO}" \
  main
