# Kubernetes Dashboard Debug Images

These images are a simple extension of the upstream [kubernetesui/dashboard](https://hub.docker.com/r/kubernetesui/dashboard) and [kubernetesui/metrics-scraper](https://hub.docker.com/r/kubernetesui/metrics-scraper) images, but with the addition of [static bash](https://github.com/robxu9/bash-static) and a modified entrypoint that starts the default kubernetes dashboard binary, but redirects any logs to `/debug.log`.

## Build the Images

You can cheat and just run the build script:

```
$ ./build.sh
```

The script will build two images: `jnsgruk/dashboard:debug` and `jnsgruk/scraper:debug` and import them into the MicroK8s container registry.

You'll also need to adjust the pebble layer configs in [`charm.py`](../src/charm.py) so that the `command` field of both the `dashboard_layer` and `scraper_layer` is set to `/entrypoint`.

You can now deploy with:

```bash
juju deploy ./jnsgruk-kubernetes-dashboard.charm \
  --resource dashboard-image=jnsgruk/dashboard:debug \
  --resource scraper-image=jnsgruk/scraper:debug
```
