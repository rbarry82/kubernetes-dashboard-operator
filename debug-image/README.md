## Kubernetes Dashboard Debug Image

This is a simple extension of the upstream [kubernetesui/dashboard](https://hub.docker.com/r/kubernetesui/dashboard) image, but with the addition of [static bash](https://github.com/robxu9/bash-static) and a modified entrypoint that starts the default kubernetes dashboard binary, but redirects any logs to `/tmp/debug.log`.

### Usage

I was using the image like so:

```bash
# Build the image
docker build -t jnsgruk/dashboard:debug .
# Import the image into Microk8s
docker save jnsgruk/dashboard:debug | microk8s.ctr image import -
```

Next, we need to adjust the pebble layer config that the charm loads, see [`charm.py`](../src/charm.py):

```python
def _dashboard_layer(self) -> dict:
        """Returns initial Pebble configuration layer for Kubernetes Dashboard"""

        cmd = [
            "/dashboard",
            "--insecure-bind-address=0.0.0.0",
            "--bind-address=0.0.0.0",
            "--auto-generate-certificates",
            f"--namespace={self.model.name}",
        ]
        return {
            "summary": "dashboard layer",
            "description": "pebble config layer for kubernetes dashboard",
            "services": {
                "dashboard": {
                    "override": "replace",
                    "summary": "kubernetes dashboard",
                    # "command": " ".join(cmd),
                    "command": "/entrypoint", # Uncomment this line!!
                    "startup": "enabled",
                    "environment": {},
                }
            },
        }
```

You can now deploy with:

```bash
juju deploy ./jnsgruk-kubernetes-dashboard.charm --resource dashboard-image=jnsgruk/dashboard:debug \
```
