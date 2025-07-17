local launchpad = import './pipelines/launchpad.libsonnet';
local pipedream = import 'github.com/getsentry/gocd-jsonnet/libs/pipedream.libsonnet';

local pipedream_config = {
  name: 'launchpad',
  auto_deploy: true,
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
    stage: 'deploy-primary',
    elastic_profile_id: 'launchpad',
  },
};

pipedream.render(pipedream_config, launchpad)
