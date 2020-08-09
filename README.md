# Sysdig AIO Image Scanner
The Sysdig AIO Image Scanner is built ontop of the anchore inline-scan ci-tools - https://github.com/anchore/ci-tools/blob/master/Dockerfile

The intent of providing the AIO Image Scanner is to provide support for multiple container runtimes such as Docker and the Open Container Initiative (OCI) and without the need for container-in-container support.

The Sysdig AIO Image Scanner can be executed using the following script -

* skopeo-analyze
  - skopeo_image_analysis.sh - uses skopeo  (https://github.com/containers/skopeo)

The provided scripts are useful for performing local analysis on container images (both from registries and locally built) and post the result of the analysis to Sysdig Secure.

## Minimum Requirements
* Sysdig Secure > v2.5.0 access (with token)
* Internet Access to post results to Sysdig Secure

---
### Options

The script/docker image supports other options that can be set during execution.

#### PDF Output (-R)

You can save the report as PDF via `-R <PATH>`.
The `<PATH>` should be an existing directory in which the report PDF will be created.

**Note:** when using the scanner via docker run, remember to mount the container local path with the host one.
Eg:
```
docker run [...] -v "$PWD/hostfolder:/tmp/containerfolder" [...] -s [...] -R "/tmp/containerfolder" <FULL_IMAGE_NAME>
```
In this way, you'll be able to get the PDF even when the container exits.

#### Complete list

For more control and options, please refer to help documentation
```
    $ skopeo_image_analysis.sh help

    Sysdig Inline Analyzer --

    Script for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
    After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
    using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.
        
      Usage: skopeo_image_analysis.sh [ OPTIONS ] <FULL_IMAGE_TAG>
    
        -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
        -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                   If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
        -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
        -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
        -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
        -i <TEXT>  [optional] Specify image ID used within Anchore Engine (ex: -i '<64 hex characters>')
        -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
        -t <TEXT>  [optional] Specify timeout for image analysis in seconds. Defaults to 300s. (ex: -t 500)
        -R <PATH>  [optional] Download scan result pdf in a specified local directory (ex: -R /staging/reports)
        -C         [optional] Delete the image from Sysdig Secure if the scan fails
        -src_creds <TEXT>  [optional] Specify registry credentials. Use USERNAME[:PASSWORD] for accessing the registry
        -auth_file <PATH>  [optional] path of the authentication file, using auth.json.
```

---

## Output Example

#### Analyze the image and post the results to Sysdig Secure.

    $ skopeo_image_analysis.sh -s https://secure.sysdig.com -k <token> docker.io/alpine:3.10

      Retrieving image -- docker.io/alpine:3.10
      
      Using anonymous authentication...
      
      SUCCESS - using full image name - docker.io/alpine
      
      SUCCESS - using image tag - 2.6
      
      SUCCESS - using sha256 digest - sha256:f0e9534a598e501320957059cb2a23774b4d4072e37c7b2cf7e95b241f019e35
      
      Getting image source signatures
      Copying blob 21c83c524219 done
      Copying config be4e4bea2c [======================================] 1.5KiB / 1.5KiB
      Writing manifest to image destination
      Storing signatures
      
      SUCCESS - prepared image archive -- /anchore-engine/alpine-2.6.tar
      
      SUCCESS - using image id - be4e4bea2c2e15b403bb321562e78ea84b501fb41497472e91ecb41504e8a27c
      
      
      Starting Analysis for docker.io/alpine:2.6...
      
      
      Analyzing docker.io/alpine:3.10...
      
      [MainThread] [anchore_engine.configuration.localconfig/validate_config()] [WARN] no webhooks defined in configuration file - notifications will be disabled
      [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/alpine:2.6 fulldigest=docker.io/alpine@sha256:f0e9534a598e501320957059cb2a23774b4d4072e37c7b2cf7e95b241f019e35
       Analysis complete!
      
      
      Sending analysis archive to https://secure.sysdig.com/api/scanning/v1
      
      
      Sysdig Image Scan Report Summary
      [
       {
        "sha256:f0e9534a598e501320957059cb2a23774b4d4072e37c7b2cf7e95b241f019e35": {
         "docker.io/alpine:2.6": [
          {
           "detail": {},
           "last_evaluation": "2020-08-07T00:40:26Z",
           "policyId": "default",
           "status": "pass"
          }
         ]
        }
       }
      ]
      Status is pass
      View the full result @ https://secure.sysdig.com/#/scanning/scan-results/docker.io%2Falpine%3A2.6/sha256:f0e9534a598e501320957059cb2a23774b4d4072e37c7b2cf7e95b241f019e35/summaries
      PDF report of the scan results can be generated with -R option.
      Removing temporary folder created /tmp/sysdig
      Finishing with return value of 0

##### Sample scan results report in PDF format
<img width="1377" alt="node-scan-result-pg1" src="https://user-images.githubusercontent.com/39659445/76037687-8dae4780-5efc-11ea-9f26-9347a5c4334c.png">

