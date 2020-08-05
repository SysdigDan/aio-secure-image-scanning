## Tekton Task Run Deployment
### Setup Project and Service Account
```
oc new-project sysdig-inline-scan
oc -n sysdig-inline-scan create serviceaccount sysdig-account
oc -n sysdig-inline-scan create secret generic sysdig-secret --from-literal secure-token="${SYSDIG_TOKEN}
```
```
oc adm policy add-cluster-role-to-user customer-admin-cluster system:serviceaccount:sysdig-inline-scan:sysdig-account
oc adm policy add-scc-to-user privileged system:serviceaccount:sysdig-inline-scan:sysdig-account
oc adm policy add-scc-to-user hostaccess system:serviceaccount:sysdig-inline-scan:sysdig-account
```
### Deploy Tekton Task
```
oc create -f tekton/tekton_taskrun.yaml
```
