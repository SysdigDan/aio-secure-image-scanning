# Sysdig AIO Image Scanner
The Sysdig AIO Image Scanner is built ontop of the anchore inline-scan ci-tools - https://github.com/anchore/ci-tools/blob/master/Dockerfile

The intent of providing the AIO Image Scanner is to provide support for multiple container runtimes such as Docker and the Open Container Initiative (OCI) and without the need for container-in-container support.

The Sysdig AIO Image Scanner can be executed using the following scripts depending on the platform in use -

* buildah-analyze
  - buildah_image_analysis.sh - uses buildah (https://github.com/containers/buildah)
    
* skopeo-analyze
  - skopeo_image_analysis.sh - uses skopeo  (https://github.com/containers/skopeo)

The provided scripts are useful for performing local analysis on container images (both from registries and locally built) and post the result of the analysis to [Sysdig Secure](https://sysdig.com/products/kubernetes-security/).

## Minimum Requirements
* Sysdig Secure > v2.5.0 access (with token)
* Internet Access to post results to Sysdig Secure
