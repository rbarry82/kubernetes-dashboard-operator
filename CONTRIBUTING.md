# Contributing

## Overview

This documents explains the processes and practices recommended for contributing enhancements to
the Kubernetes Dashboard charm.

- Generally, before developing enhancements to this charm, you should consider [opening an issue
  ](https://github.com/jnsgruk/kubernetes-dashboard-operator/issues) explaining your use case.
- If you would like to chat with us about your use-cases or proposed implementation, you can reach
  us at [Canonical Mattermost public channel](https://chat.charmhub.io/charmhub/channels/charm-dev)
  or [Discourse](https://discourse.charmhub.io/). The primary author of this charm is available on
  the Mattermost channel as `@jnsgruk`.
- Familiarising yourself with the [Charmed Operator Framework](https://juju.is/docs/sdk) library
  will help you a lot when working on new features or bug fixes.
- All enhancements require review before being merged. Code review typically examines
  - code quality
  - test coverage
  - user experience for Juju administrators this charm.
- Please help us out in ensuring easy to review branches by rebasing your pull request branch onto
  the `main` branch. This also avoids merge commits and creates a linear Git commit history.

## Developing

You can use the environments created by `tox` for development:

```shell
tox --notest -e unit
source .tox/unit/bin/activate
```

### Testing

```shell
tox -e fmt           # update your code according to linting rules
tox -e lint          # code style
tox -e unit          # unit tests
tox -e integration   # integration tests
tox                  # runs 'lint' and 'unit' environments
```

## Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

```bash
# Create a model
juju add-model dashboard
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm
juju deploy --trust ./kubernetes-dashboard_ubuntu-20.04-amd64.charm \
  --resource dashboard-image=kubernetesui/dashboard:v2.4.0 \
  --resource scraper-image=kubernetesui/metrics-scraper:v1.0.7
```

If, for some reason the charm fails to clean up the Kubernetes resources it creates, they can be
removed as follows:

```bash
kubectl -n dashboard delete serviceaccount kubernetes-dashboard
kubectl -n dashboard delete svc kubernetes-dashboard
kubectl -n dashboard delete svc kubernetes-dashboard-metrics-scraper
kubectl -n dashboard delete secret kubernetes-dashboard-certs
kubectl -n dashboard delete secret kubernetes-dashboard-csrf
kubectl -n dashboard delete secret kubernetes-dashboard-key-holder
kubectl -n dashboard delete cm kubernetes-dashboard-settings
kubectl -n dashboard delete role kubernetes-dashboard
kubectl -n dashboard delete rolebinding kubernetes-dashboard
kubectl delete clusterrole kubernetes-dashboard
kubectl delete clusterrolebindings kubernetes-dashboard
```
