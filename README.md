# Kubernetes Dashboard Operator (Sidecar Edition)

This charm is a demonstration of the new Sidecar Charm pattern for Juju 2.9. It uses [Pebble](https://github.com/canonical/pebble) and the [Charmed Operator Framework](https://juju.is/docs/sdk).

This charm deploys and operates the [Kubernetes Dashboard](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/).

## Getting Started

Setup a test environment with MicroK8s:

```bash
# Install MicroK8s
$ sudo snap install --classic microk8s
# Add your current user to the 'microk8s' group
$ sudo usermod -aG microk8s $(whoami)
# Enable some required MicroK8s addons
$ sudo microk8s enable storage dns
# Alias the bundled MicroK8s kubectl binary
$ sudo snap alias microk8s.kubectl kubectl
# Make the new user group addition effective now for the current shell
$ newgrp microk8s
```

Next, install Juju and deploy the Kubernetes Dashboard:

```bash
$ sudo snap refresh juju --channel=latest/stable
# Bootstrap a Juju controller onto MicroK8s
$ juju bootstrap microk8s micro
# Create a model for our deployment
$ juju add-model dashboard

# Deploy!
$ juju deploy jnsgruk-kubernetes-dashboard --channel=edge

# If your cluster has RBAC enabled, you'll need to
# trust the app to give it the requisite K8s privileges
$ juju trust jnsgruk-kubernetes-dashboard --scope=cluster

# Wait for the deployment to complete
$ watch -n1 --color "juju status --color"
```

You should end up with some output like the following:

```
❯ juju status
Model      Controller  Cloud/Region        Version  SLA          Timestamp
dashboard  micro       microk8s/localhost  2.9.0    unsupported  15:28:05+01:00

App                           Version  Status  Scale  Charm                         Store  Channel  Rev  OS          Address  Message
jnsgruk-kubernetes-dashboard           active      1  jnsgruk-kubernetes-dashboard  local             1  kubernetes

Unit                             Workload  Agent  Address       Ports  Message
jnsgruk-kubernetes-dashboard/0*  active    idle   10.1.215.204
```

You can now visit (using the example above): https://10.1.215.204:8443 and login to the dashboard. Your browser will display a warning about the certificate being self-signed. You can safely ignore this - the charm will generate a self-signed certificate before starting the Kubernetes Dashboard.

## Development

To contribute to this charm, in addition to the tools listed in the getting started above, you'll need to install [`charmcraft`](https://github.com/canonical/charmcraft):

```bash
# Install charmcraft from the snap store
$ sudo snap install charmcraft

# Clone the source code of the charm
$ git clone https://github.com/jnsgruk/charm-kubernetes-dashboard
$ cd charm-kubernetes-dashboard

# Build the charm
$ charmcraft pack

# Deploy
$ juju deploy ./jnsgruk-kubernetes-dashboard.charm \
    --resource dashboard-image=kubernetesui/dashboard:v2.2.0 \
    --resource scraper-image=kubernetesui/metrics-scraper:v1.0.6
```

## Known Issues

- Due to [this issue](https://bugs.launchpad.net/juju/+bug/1926568), the `stop` and `remove` hooks do not always fire correctly. In this case, that results in the various Kubernetes resources that are created by the charm not being removed successfully. For now, there is an action that can be run to remove all created Kubernetes resources prior to removal of the application:

```
$ juju run-action jnsgruk-kubernetes-dashboard/0 delete-resources
```

## TODO

- [x] Fix the broken default generated certificates when none are specified
- [x] Include the metrics scraper container in the deployment
- [ ] Add support for the ingress relation
- [ ] Add support for custom TLS certificates from a pre-existing Kubernetes secret
- [ ] Add some unit testing
- [ ] Add some functional tests
