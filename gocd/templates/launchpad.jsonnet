local launchpad = import './pipelines/launchpad.libsonnet';
local pipedream = import 'github.com/getsentry/gocd-jsonnet/libs/pipedream.libsonnet';

local pipedream_config = {
  name: 'launchpad',
  auto_deploy: true,
  exclude_regions: [
    'de',
    'us',
    'customer-1',
    'customer-2',
    'customer-4',
    'customer-7',
  ],
  materials: {
    launchpad_repo: {
      git: 'git@github.com:getsentry/launchpad.git',
      shallow_clone: true,
      branch: 'main',
      destination: 'launchpad',
    },
  },
  rollback: {
    material_name: 'launchpad_repo',
    stage: 'deploy_primary',
    elastic_profile_id: 'launchpad',
  },
};

pipedream.render(pipedream_config, launchpad)
