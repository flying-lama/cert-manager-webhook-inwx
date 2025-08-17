[![Go Report Card](https://goreportcard.com/badge/github.com/flying-lama/cert-manager-webhook-inwx)](https://goreportcard.com/report/github.com/flying-lama/cert-manager-webhook-inwx)
[![License](https://img.shields.io/github/license/flying-lama/cert-manager-webhook-inwx)](https://github.com/flying-lama/cert-manager-webhook-inwx/blob/main/LICENSE)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/flying-lama/cert-manager-webhook-inwx)

cert-manager-webhook-inwx
===========================

[cert-manager](https://cert-manager.io) webhook implementation for use
with [INWX](https://www.inwx.de) provider for solving [ACME DNS-01 challenges](https://cert-manager.io/docs/configuration/acme/dns01/).

Usage
-----

For the INWX-specific configuration, you will need to create a Kubernetes
secret, containing your username, password and OTP key (optional).

You can do it like following, just place the correct values in the command (vars can be scripted with your password manager CLI):

```bash
INWX_USERNAME=$(echo "username") ;\
INWX_PASSWORD=$(echo "password") ; \
INWX_OTP_KEY=$(echo "otp") ; \
kubectl create secret generic inwx-credentials \
    --namespace cert-manager \
    --from-literal=username="$INWX_USERNAME" \
    --from-literal=password="$INWX_PASSWORD" \
    --from-literal=otpKey="$INWX_OTP_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
```

After creating the secret, configure the ``Issuer``/``ClusterIssuer`` of
yours to have the following configuration:
```yml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer # or "Issuer"
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: test@example.com
    profile: tlsserver
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - dns01:
          webhook:
            groupName: de.inwx.webhook
            solverName: inwx
            config:
              username:
                secretKeyRef:
                  name: inwx-credentials
                  key: username
              password:
                secretKeyRef:
                  name: inwx-credentials
                  key: password
              otpKey:
                otpKeySecretKeyRef:
                  name: inwx-credentials
                  key: otpKey
```
For more details, please refer to https://cert-manager.io/docs/configuration/acme/dns01/#configuring-dns01-challenge-provider

Now, the actual webhook can be installed via Helm chart:
```
helm repo add flying-lama-cert-manager-webhook-inwx https://flying-lama.github.io/cert-manager-webhook-inwx

helm install cert-manager-webhook-inwx flying-lama-cert-manager-webhook-inwx/cert-manager-webhook-inwx --namespace cert-manager
```
From that point, the issuer configured above should be able to solve
the DNS01 challenges using ``cert-manager-webhook-inwx``.


License
-------

[Apache 2 License](./LICENSE)


