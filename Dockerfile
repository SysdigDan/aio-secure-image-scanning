FROM anchore/inline-scan:v0.7.3

MAINTAINER SysdigDan <daniel.moloney@sysdig.com>

USER root

COPY scripts/skopeo_image_analysis.sh \
scripts/docker-entrypoint.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/skopeo_image_analysis.sh \
&& chmod +x /usr/local/bin/docker-entrypoint.sh 

# To be able to run under an anonymous user, give these folders group writeable access
# for root group
RUN chgrp -R 0 /analysis_scratch && chmod 775 /analysis_scratch \
&& chgrp -R 0 /anchore-engine && chmod 775 /anchore-engine \
&& chgrp -R 0 /anchore_service && chmod 775 /anchore_service

# On OpenShift, unless privileged execution of some type, this will get ignored and the 
# container will run as an anonymous user in the root (0) group
USER anchore:anchore

ENTRYPOINT ["docker-entrypoint.sh"]
