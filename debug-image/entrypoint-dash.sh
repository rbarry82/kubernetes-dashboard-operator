#!/bash
/dashboard \
  --bind-address=0.0.0.0 \
  --namespace=dashboard \
  --tls-cert-file=tls.crt \
  --tls-key-file=tls.key \
  --sidecar-host=http://localhost:8000 >>/debug.log 2>&1