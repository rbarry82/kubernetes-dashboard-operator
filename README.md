## Kubernetes Dashboard Operator (Sidecar Edition)

This charm is a demonstration of the new Sidecar Charm pattern for Juju 2.9. It uses [Pebble](https://github.com/canonical/pebble) and the [Python Operator Framework](https://pythonoperatorframework.io).

This charm deploys and operates the [Kubernetes Dashboard](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/).

At present, this charm cannot be published to Charmhub, so you will need to build it locally. To setup a local test environment with [MicroK8s](https://microk8s.io), do the following:

```bash
$ sudo snap install --classic microk8s
$ sudo usermod -aG microk8s $(whoami)
$ sudo microk8s enable storage dns
$ sudo snap alias microk8s.kubectl kubectl
$ newgrp microk8s
```

Next install Charmcraft and build the Charm

```bash
# Install Charmcraft
$ sudo snap install charmcraft --edge

# Clone an example charm
$ git clone https://github.com/jnsgruk/charm-kubernetes-dashboard
# Build the charm
$ cd charm-kubernetes-dashboard
$ charmcraft build
```

Now you're ready to deploy the Charm:

```bash
# For now, we require the 2.9/candidate channel until features land in candidate/stable
$ sudo snap refresh juju --channel=2.9/candidate
# Create a model for our deployment
$ juju add-model dashboard

# Deploy!
$ juju deploy ./kubernetes-dashboard-operator.charm \
    --resource dashboard-image=kubernetesui/dashboard:v2.0.0 \
    --config kube-config="$(microk8s config)"
# Wait for the deployment to complete
$ watch -n1 --color "juju status --color"
```

This will take a few moments, and take the following steps:

- Create the deployment as per usual sidecar charms
- Create Kubernetes specific resources on the install hook
- Patch the StatefulSet that Juju deploys to include the ServiceAccount mounts

You should end up with some output like the following:

```
❯ juju status
Model      Controller  Cloud/Region        Version  SLA          Timestamp
dashboard  micro       microk8s/localhost  2.9-rc9  unsupported  15:21:57+01:00

App       Version  Status  Scale  Charm                 Store  Channel  Rev  OS      Address  Message
k8s-dash           active      1  kubernetes-dashboard  local            30  ubuntu

Unit         Workload  Agent  Address       Ports  Message
k8s-dash/0*  active    idle   10.1.215.217
```

You can now visit (using the example above): https://10.1.215.217:8443 and login to the dashboard

**NOTE**: See known issues, but you won't be able to visit the URL in Chrome. Somewhere the certificates are being generated incorrectly and Chrome will not let you pass -- you can test in Firefox.

### Current Limitations/Known Issues

- The metrics pod usually deployed with the dashboard needs to be charmed seperately (and probably deployed with a bundle alongside this charm)
- The certficate generated for the dashboard is invalid, Google Chrome will not let you visit the URL by default
- No ability to pass service tokens through, hence passing the `kubeconfig` as a config item
- No unit tests - waiting on support for Sidecar Charms in the Operator Framework ([see issue](https://github.com/canonical/operator/issues/488))
