local gocdtasks = import 'github.com/getsentry/gocd-jsonnet/libs/gocd-tasks.libsonnet';

function(region) {
  environment_variables: {
    // k8s-deploy dispatches deployment workflows using GitHub App credentials.
    GITHUB_APP_ID: '{{SECRET:[devinfra-github][app_id]}}',
    GITHUB_APP_PRIVATE_KEY: '{{SECRET:[devinfra-github][private_key]}}',
    // SENTRY_REGION is used by the dev-infra scripts to connect to GKE
    SENTRY_REGION: region,
  },
  materials: {
    launchpad_repo: {
      git: 'git@github.com:getsentry/launchpad.git',
      shallow_clone: true,
      auto_update: true,
      branch: 'main',
      destination: 'launchpad',
    },
  },
  lock_behavior: 'unlockWhenFinished',
  stages: [
    {
      pending_cloudbuild_upload: {
        fetch_materials: true,
        jobs: {
          deploy: {
            timeout: 1200,
            elastic_profile_id: 'launchpad',
            tasks: [
              gocdtasks.script(importstr '../bash/check-cloudbuild.sh'),
            ],
          },
        },
      },
    },
    {
      'deploy-canary': {
        approval: {
          type: 'success',
        },
        fetch_materials: true,
        jobs: {
          deploy: {
            timeout: 1200,
            elastic_profile_id: 'launchpad',
            environment_variables: {
              LABEL_SELECTOR: 'service=launchpad,env=canary',
            },
            tasks: [
              gocdtasks.script(importstr '../bash/deploy.sh'),
            ],
          },
        },
      },
    },
    {
      'deploy-primary': {
        approval: {
          type: 'success',
        },
        fetch_materials: true,
        jobs: {
          deploy: {
            timeout: 1200,
            elastic_profile_id: 'launchpad',
            environment_variables: {
              LABEL_SELECTOR: 'service=launchpad',
            },
            tasks: [
              gocdtasks.script(importstr '../bash/deploy.sh'),
            ],
          },
        },
      },
    },
  ],
}
