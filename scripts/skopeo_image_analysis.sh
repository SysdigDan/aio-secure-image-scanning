#!/usr/bin/env bash

set -Eeo pipefail

########################
### GLOBAL VARIABLES ###
########################

export TIMEOUT=${TIMEOUT:=300}
# defaults for variables set by script options
IMAGE_ID=""
ANALYZE_CMD=()
DOCKERFILE="/anchore-engine/Dockerfile"
MANIFEST_FILE="/anchore-engine/manifest.json"
# sysdig option variables
SYSDIG_BASE_SCANNING_URL="https://secure.sysdig.com"
SYSDIG_SCANNING_URL="http://localhost:9040/api/scanning"
SYSDIG_ANCHORE_URL="http://localhost:9040/api/scanning/v1/anchore"
SYSDIG_ANNOTATIONS="foo=bar"
SYSDIG_IMAGE_DIGEST_SHA="sha256:123456890abcdefg"
SYSDIG_IMAGE_ID="123456890abcdefg"
SCAN_IMAGE=()
FAILED_IMAGE=()
PDF_DIRECTORY=$(echo $PWD)
GET_CALL_STATUS=""
GET_CALL_RETRIES=300
SRC_CREDS=""
AUTH_FILE=""
DETAIL=false
TMP_PATH="/tmp/sysdig"
PDF_DIRECTORY=""

display_usage() {
cat << EOF

Sysdig Inline Analyzer --

Script for performing analysis on local docker images, utilizing Anchore Engine analyzer subsystem.
After image is analyzed, the resulting Anchore image archive is sent to a remote Anchore Engine installation
using the -r <URL> option. This allows inline_analysis data to be persisted & utilized for reporting.
Images should be built & tagged locally.

  Usage: ${0##*/} [ OPTIONS ] <FULL_IMAGE_TAG>
  
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
    
EOF
}

main() {
  trap 'error' ERR
  trap 'cleanup' EXIT SIGTERM
  trap 'interupt' SIGINT

  get_and_validate_options "$@"
  get_and_validate_image
  inspect_archive_image
  prepare_sysdig_user
  start_image_analysis
}

get_and_validate_options() {
  # Transform long options to short ones
  for arg in "$@"; do
    shift
    case "$arg" in
      "-src_creds") set -- "$@" "-x" ;;
      "-auth_file") set -- "$@" "-y" ;;
      *)        set -- "$@" "$arg"
    esac
  done

  
  # parse options
  while getopts ':k:s:a:d:i:f:m:t:x:y:R:Ch' option; do
      case "${option}" in
          k  ) k_flag=true; SYSDIG_API_TOKEN="${OPTARG}";;
          s  ) s_flag=true; SYSDIG_BASE_SCANNING_URL="${OPTARG%%}";;
          a  ) a_flag=true; SYSDIG_ANNOTATIONS="${OPTARG}";;
          d  ) d_flag=true; SYSDIG_IMAGE_DIGEST_SHA="${OPTARG}";;
          i  ) i_flag=true; SYSDIG_IMAGE_ID="${OPTARG}";;
          f  ) f_flag=true; DOCKERFILE="/anchore-engine/$(basename ${OPTARG})";;
          m  ) m_flag=true; MANIFEST_FILE="/anchore-engine/$(basename ${OPTARG})";;
          t  ) t_flag=true; TIMEOUT="${OPTARG}";;
          x  ) x_flag=true; SRC_CREDS="${OPTARG}";;
          y  ) y_flag=true; AUTH_FILE="${OPTARG}";;
          R  ) R_flag=true; PDF_DIRECTORY="${OPTARG}";;
          C  ) clean_flag=true;;
          h  ) display_usage; exit;;
          \? ) printf "%s\n\n" "  Invalid option: -${OPTARG}" >&2; display_usage >&2; exit 1;;
          :  ) printf "%s\n\n%s\n\n\n" "  Option -${OPTARG} requires an argument." >&2; display_usage >&2; exit 1;;
      esac
  done
  shift "$((OPTIND - 1))"

  # set SYSDIG_API_TOKEN and IMAGE_TAG from ENV if required
  if [[ -z "${k_flag}" ]]; then
    SYSDIG_API_TOKEN="${SYSDIG_API_TOKEN}"
    IMAGE_TAG="${IMAGE_TAG}"
  else
   IMAGE_TAG="$@"
  fi

  SYSDIG_SCANNING_URL="${SYSDIG_BASE_SCANNING_URL}"/api/scanning/v1
  SYSDIG_ANCHORE_URL="${SYSDIG_SCANNING_URL}"/anchore

  # Check for invalid options
  if [[ ! $(which skopeo) ]]; then
      printf '%s\n\n' 'ERROR - skopeo is not installed or cannot be found in $PATH' >&2
      display_usage >&2
      exit 1
  elif [[ "${#@}" -gt 1 ]]; then
      printf '%s\n\n' "ERROR - only 1 image can be analyzed at a time" >&2
      display_usage >&2
      exit 1
  elif [[ "${#@}" -lt 1 ]] && [[ -z "${IMAGE_TAG}" ]]; then
        printf '%s\n\n' "ERROR - must specify an image to analyze" >&2
        display_usage >&2
        exit 1
  elif [[ ! "${SYSDIG_API_TOKEN}" ]]; then
      printf '%s\n\n' "ERROR - must provide the Sysdig Secure API token" >&2
      display_usage >&2
      exit 1
  elif [[ "${SYSDIG_BASE_SCANNING_URL: -1}" == '/' ]]; then
      printf '%s\n\n' "ERROR - must specify Sysdig url - ${SYSDIG_BASE_SCANNING_URL} without trailing slash" >&2
      display_usage >&2
      exit 1
  elif ! curl -k -s --fail -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images" > /dev/null; then
      printf '%s\n\n' "ERROR - invalid combination of Sysdig secure endpoint : token provided - ${SYSDIG_SCANNING_URL} : ${SYSDIG_API_TOKEN}" >&2
      display_usage >&2
      exit 1
  elif ([[ "${m_flag}" ]] || [[ "${d_flag}" ]]); then
      printf '%s\n\n' "ERROR - cannot specify manifest file or digest when using the -g option" >&2
      display_usage >&2
      exit 1
  elif [[ "${R_flag:-}" ]] && [[ ! -d "${PDF_DIRECTORY}" ]];then
      printf '%s\n\n' "ERROR - Directory: ${PDF_DIRECTORY} does not exist" >&2
      display_usage >&2
      exit 1
  elif [[ "${R_flag:-}" ]] && [[ "${PDF_DIRECTORY: -1}" == '/' ]]; then
      printf '%s\n\n' "ERROR - must specify file path - ${PDF_DIRECTORY} without trailing slash" >&2
      display_usage >&2
      exit 1
  fi
}

get_and_validate_image() {

  printf '%s\n\n' "Retrieving image -- ${IMAGE_TAG}" >&2
  inspect_repo_image

  BASE_IMAGE_NAME=$(echo "${SYSDIG_FULL_IMAGE_NAME}" | rev | cut -d '/' -f 1 | rev)

  SAVE_FILE_NAME="${BASE_IMAGE_NAME}-${SYSDIG_IMAGE_TAG}.tar"
  # if name has a : in it, replace it with _ to avoid skopeo errors
  if [[ "${SAVE_FILE_NAME}" =~ [:] ]]; then
      SAVE_FILE_NAME="${SAVE_FILE_NAME/:/-}"
  fi
  SAVE_FILE_PATH="/anchore-engine/${SAVE_FILE_NAME}"

  if [[ -z "${SAVE_FILE_PATH}" ]]; then
    printf '%s\n\n' "ERROR - issue with archive save location for - ${IMAGE_TAG}" >&2
    display_usage >&2
    exit 1
  else
    if [[ -n ${SRC_CREDS} ]] && [[ -z ${AUTH_FILE} ]]; then
      skopeo copy --src-tls-verify=false --src-creds=${SRC_CREDS} "docker://${IMAGE_TAG}" "docker-archive:${SAVE_FILE_PATH}"
    elif [[ -z ${SRC_CREDS} ]] && [[ -n ${AUTH_FILE} ]]; then
      skopeo copy --src-tls-verify=false --authfile=${AUTH_FILE} "docker://${IMAGE_TAG}" "docker-archive:${SAVE_FILE_PATH}"
    elif [[ -z ${SRC_CREDS} ]] && [[ -z ${AUTH_FILE} ]]; then
      skopeo copy --src-tls-verify=false --src-no-creds "docker://${IMAGE_TAG}" "docker-archive:${SAVE_FILE_PATH}" 
    else
      printf '%s\n\n' "ERROR - you can only use -src_creds or -auth_file" >&2
      display_usage >&2
      exit 1
    fi
  fi

  if [[ -f "${SAVE_FILE_PATH}" ]]; then
      chmod 777 "${SAVE_FILE_PATH}"
      printf '\n%s\n\n' "SUCCESS - prepared image archive -- ${SAVE_FILE_PATH}"
  else
      printf '%s\n\n' "ERROR - unable to save image to ${SAVE_FILE_PATH}." >&2
      display_usage >&2
      exit 1
  fi
}

inspect_repo_image() {
  if [[ -n ${SRC_CREDS} ]] && [[ -z ${AUTH_FILE} ]]; then
    printf '%s\n\n' "Using authentication credentials..." >&2
    REPO_INSPECT_JSON=$(skopeo inspect --tls-verify=false --creds=${SRC_CREDS} docker://${IMAGE_TAG})
  elif [[ -z ${SRC_CREDS} ]] && [[ -n ${AUTH_FILE} ]]; then
    printf '%s\n\n' "Using authentication file..." >&2
    REPO_INSPECT_JSON=$(skopeo inspect --tls-verify=false --authfile=${AUTH_FILE} docker://${IMAGE_TAG})
  elif [[ -z ${SRC_CREDS} ]] && [[ -z ${AUTH_FILE} ]]; then
    printf '%s\n\n' "Using anonymous authentication..." >&2
    REPO_INSPECT_JSON=$(skopeo inspect --tls-verify=false --no-creds docker://${IMAGE_TAG})
  else
    printf '%s\n\n' "ERROR - you can only use -src_creds or -auth_file" >&2
    display_usage >&2
    exit 1
  fi

  if [[ -z $REPO_INSPECT_JSON ]]; then
    printf '%s\n\n' "ERROR - did not get correct response for - ${IMAGE_TAG}" >&2
    display_usage >&2
    exit 1
  fi

  SYSDIG_FULL_IMAGE_NAME=$(echo $REPO_INSPECT_JSON | jq -r '.Name')
  if [[ -z $SYSDIG_FULL_IMAGE_NAME ]]; then
    printf '%s\n\n' "ERROR - issue finding full image name in repository for - ${IMAGE_TAG}" >&2
    display_usage >&2
    exit 1
  else
    # switch docker.io vs rest-of-the-world registries
    # using (light) docker rule for naming: if it has a "." or a ":" we assume the image is from some specific registry
    # see: https://github.com/docker/distribution/blob/master/reference/normalize.go#L91
    IS_DOCKER_IO=$(echo ${IMAGE_TAG} | grep 'docker.io/library' || echo "")
    if [[ ! ${IS_DOCKER_IO} ]] && [[ ! "${SYSDIG_FULL_IMAGE_NAME}" =~ ^docker.io/library* ]]; then
        # ensure we are setting the correct full image tag
        SYSDIG_FULL_IMAGE_NAME=${SYSDIG_FULL_IMAGE_NAME}
    else
        SYSDIG_FULL_IMAGE_NAME="docker.io/$(echo ${SYSDIG_FULL_IMAGE_NAME} | rev |  cut -d / -f 1 | rev)"
    fi

    printf '%s\n\n' "SUCCESS - using full image name - ${SYSDIG_FULL_IMAGE_NAME}" >&2
  fi

  SYSDIG_IMAGE_TAG=$(echo $REPO_INSPECT_JSON | jq -r '.RepoTags[0]')
  if [[ -z $SYSDIG_IMAGE_TAG ]]; then
    printf '%s\n\n' "ERROR - issue finding image tag in repository for - ${IMAGE_TAG}" >&2
    display_usage >&2
    exit 1
  else
    printf '%s\n\n' "SUCCESS - using image tag - ${SYSDIG_IMAGE_TAG}" >&2
  fi

  if [[ ! "${d_flag-""}" ]]; then
    SYSDIG_IMAGE_DIGEST_SHA=$(echo $REPO_INSPECT_JSON | jq -r '.Digest')
    if [[ -z $SYSDIG_IMAGE_DIGEST_SHA ]]; then
      printf '%s\n\n' "ERROR - issue finding sha256 digest in repository for - ${IMAGE_TAG}" >&2
      display_usage >&2
      exit 1
    else
      printf '%s\n\n' "SUCCESS - using sha256 digest - ${SYSDIG_IMAGE_DIGEST_SHA}" >&2
    fi
  fi
}

inspect_archive_image() {
  IMAGE_INSPECT_RAW_JSON=$(skopeo inspect --raw docker-archive:${SAVE_FILE_PATH})
  if [[ -z $IMAGE_INSPECT_RAW_JSON ]]; then
    printf '%s\n\n' "ERROR - issue finding image archive locally for - ${IMAGE_TAG}" >&2
    display_usage >&2
    exit 1
  fi

  if [[ ! "${i_flag-""}" ]]; then
    SYSDIG_IMAGE_ID=$(echo $IMAGE_INSPECT_RAW_JSON | jq -r '.config.digest')
    if [[ -z $SYSDIG_IMAGE_ID ]]; then
      printf '%s\n\n' "ERROR - issue finding image id from archive file for - ${IMAGE_TAG}" >&2
      display_usage >&2
      exit 1
    else
      SYSDIG_IMAGE_ID=$(echo $SYSDIG_IMAGE_ID | cut -d ':' -f 2)
      printf '%s\n\n' "SUCCESS - using image id - ${SYSDIG_IMAGE_ID}" >&2
    fi
  fi
}

prepare_sysdig_user() {
  # finally, get the account from Sysdig for the input username
  mkdir -p /tmp/sysdig
  HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/account")
  if [[ "${HCODE}" == 404 ]]; then
      HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL%%/}/account")
  fi

  if [[ "${HCODE}" == 200 ]] && [[ -f "/tmp/sysdig/sysdig_output.log" ]]; then
      SYSDIG_ACCOUNT=$(cat /tmp/sysdig/sysdig_output.log | grep '"name"' | awk -F'"' '{print $4}')
  else
      printf '%s\n\n' "ERROR - unable to fetch account information from anchore-engine for specified user"
      if [[ -f /tmp/sysdig/sysdig_output.log ]]; then
          printf '%s\n\n\n' "***SERVICE RESPONSE****">&2
          cat /tmp/sysdig/sysdig_output.log >&2
          printf '\n%s\n\n' "***END SERVICE RESPONSE****" >&2
      fi
  #exit 1
  fi
}

start_image_analysis() {
  SYSDIG_FULL_IMAGE_TAG="${SYSDIG_FULL_IMAGE_NAME}:${SYSDIG_IMAGE_TAG}"

  get_scan_result_code

  if [[ "${GET_CALL_STATUS}" != 200 ]]; then
    run_image_analysis

    if [[ -f "/anchore-engine/image-analysis-archive.tgz" ]]; then
      printf '%s\n\n' " Analysis complete!"
      printf '\n%s\n\n' "Sending analysis archive to ${SYSDIG_SCANNING_URL%%/}"
      submit_image_analysis
    else
      printf '%s\n\n' "ERROR Cannot find image analysis archive. An error occured during analysis."  >&2
      display_usage >&2
      exit 1
    fi
  else
    echo "Image digest found on Sysdig Secure, skipping analysis."
  fi
  get_scan_result_with_retries
}

run_image_analysis() {
  printf '\n%s\n\n' "Starting Analysis for ${SYSDIG_FULL_IMAGE_TAG}..."

  if [[ ! -f "${SAVE_FILE_PATH}" ]]; then
      printf '%s\n\n' "ERROR - Could not find file: ${SAVE_FILE_PATH}" >&2
      display_usage >&2
      exit 1
  fi

  # analyze image with anchore-engine
  ANALYZE_CMD=('anchore-manager analyzers exec')
  ANALYZE_CMD+=('--tag "${SYSDIG_FULL_IMAGE_TAG}"')
  ANALYZE_CMD+=('--digest "${SYSDIG_IMAGE_DIGEST_SHA}"')
  ANALYZE_CMD+=('--image-id "${SYSDIG_IMAGE_ID}"')
  ANALYZE_CMD+=('--account-id "${SYSDIG_ACCOUNT}"')

  if [[ "${a_flag-""}" ]]; then
      ANALYZE_CMD+=('--annotation "${SYSDIG_ANNOTATIONS},added-by=sysdig-aio-inline-scanner"')
  else
      ANALYZE_CMD+=('--annotation "added-by=sysdig-aio-inline-scanner"')
  fi

  ANALYZE_CMD+=('"$SAVE_FILE_PATH" /anchore-engine/image-analysis-archive.tgz > /dev/null')

  printf '\n%s\n\n' "Analyzing ${IMAGE_TAG}..."
  eval "${ANALYZE_CMD[*]}"
}

submit_image_analysis() {
  # Posting the archive to the secure backend
  HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST_SHA}" -H "imageName: ${SYSDIG_FULL_IMAGE_TAG}" -F "archive_file=@/anchore-engine/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/import/images")

  if [[ "${HCODE}" != 200 ]]; then
      printf '%s\n\n' "ERROR - unable to POST ${analysis_archive_name} to ${SYSDIG_SCANNING_URL%%/}/import/images" >&2
      if [ -f /tmp/sysdig/sysdig_output.log ]; then
          printf '%s\n\n\n' "***SERVICE RESPONSE****">&2
          cat /tmp/sysdig/sysdig_output.log >&2
          printf '\n%s\n\n' "***END SERVICE RESPONSE****" >&2
      fi
      exit 1
  fi
  get_scan_result_with_retries
}

get_scan_result_code() {
  GET_CALL_STATUS=$(curl -sk -o /dev/null --write-out "%{http_code}" --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=${DETAIL}")
}

get_scan_result_with_retries() {
  # Fetching the result of scanned digest
  for ((i=0;  i<${GET_CALL_RETRIES}; i++)); do
      get_scan_result_code
      if [[ "${GET_CALL_STATUS}" == 200 ]]; then
          status=$(curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=${DETAIL}" | grep "status" | cut -d : -f 2 | awk -F\" '{ print $2 }')
          break
      fi
      echo -n "." && sleep 1
  done

  printf "\nSysdig Image Scan Report Summary \n"
  curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=${DETAIL}"

  if [[ "${R_flag-""}" ]]; then
      printf "\nDownloading PDF Scan result for image id: ${SYSDIG_IMAGE_ID} / digest: ${SYSDIG_IMAGE_DIGEST_SHA}"
      get_scan_result_pdf_by_digest
  fi

  if [[ "${status}" = "pass" ]]; then
      printf "\nStatus is pass\n"
      print_scan_result_summary_message
      exit 0
  else
      printf "\nStatus is fail\n"
      print_scan_result_summary_message
      if [[ "${clean_flag:-}" ]]; then
          echo "Cleaning image from Anchore"
          curl -X DELETE -s -k -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}?force=true"
      fi
      exit 1
  fi
}

print_scan_result_summary_message() {
  if [[ ! "${R_flag-""}" ]]; then
      if [[ ! "${status}" = "pass" ]]; then
          echo "Result Details: "
          curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_NAME}&detail=true"
      fi
  fi

  if [[ -z "${clean_flag:-}" ]]; then
      ENCODED_TAG=$(urlencode ${SYSDIG_FULL_IMAGE_TAG})
      if [[ "${o_flag:-}" ]]; then
          echo "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/secure/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST_SHA}/summaries"
      else
          echo "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST_SHA}/summaries"
      fi
  fi
  printf "PDF report of the scan results can be generated with -R option.\n"
}

get_scan_result_pdf_by_digest() {
  date_format=$(date +'%Y-%m-%d')
  curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -o "${PDF_DIRECTORY}/${date_format}-${SYSDIG_FULL_IMAGE_NAME##*/}-scan-result.pdf" "${SYSDIG_SCANNING_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/report?tag=${SYSDIG_FULL_IMAGE_TAG}"
}

urlencode() {
  # urlencode <string>
  local length="${#1}"
  for (( i = 0; i < length; i++ )); do
      local c="${1:i:1}"
      case $c in
          [a-zA-Z0-9.~_-]) printf "$c" ;;
          *) printf '%%%02X' "'$c"
      esac
  done
}

interupt() {
  cleanup 130
}

error() {
  local ret=$?
  echo "[$0] An error occured during the execution of the script"
  cleanup ${ret}
}

cleanup() {
  local ret="${1:-${?}}"

  set +e

  echo "Removing temporary folder created ${TMP_PATH}"
  rm -rf "${TMP_PATH}"
  rm -f "${SAVE_FILE_PATH}"

  echo "Finishing with return value of ${ret}"
  exit "${ret}"
}

main "$@"
