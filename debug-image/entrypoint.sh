#!/bash
# /dashboard --insecure-bind-address=0.0.0.0 --bind-address=0.0.0.0 --auto-generate-certificates --kubeconfig=/kube-config --namespace=dashboard >/tmp/debug.log 2>&1
/dashboard \
  --insecure-bind-address=0.0.0.0 \
  --bind-address=0.0.0.0 \
  --auto-generate-certificates \
  --log_dir=/tmp \
  --namespace=dashboard >/debug.log 2>&1