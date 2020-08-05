FROM anchore/inline-scan:v0.7.3

MAINTAINER SysdigDan <daniel.moloney@sysdig.com>

USER root

ENV BUILDAH_ISOLATION=chroot

RUN subscription-manager config --rhsm.auto_enable_yum_plugins=0 \
&& sed -i 's/enabled=1/enabled=0/g' /etc/yum/pluginconf.d/subscription-manager.conf \
&& sed -i 's/enabled=1/enabled=0/g' /etc/yum/pluginconf.d/product-id.conf

RUN dnf -y install http://mirror.centos.org/centos-8/8.2.2004/BaseOS/x86_64/os/Packages/centos-gpg-keys-8.2-2.2004.0.1.el8.noarch.rpm \
&& dnf -y install http://mirror.centos.org/centos-8/8.2.2004/BaseOS/x86_64/os/Packages/centos-repos-8.2-2.2004.0.1.el8.x86_64.rpm

RUN dnf -y reinstall shadow-utils \
&& dnf -y install fuse-overlayfs buildah \
&& dnf -y clean all

RUN rm -rf /var/cache /var/log/dnf* /var/log/yum.*

COPY containers.conf /etc/containers/

# Adjust storage.conf to enable Fuse storage.
RUN chmod 644 /etc/containers/containers.conf; sed -i -e 's|^#mount_program|mount_program|g' -e '/additionalimage.*/a "/var/lib/shared",' -e 's|^mountopt[[:space:]]*=.*$|mountopt = "nodev,fsync=0"|g' /etc/containers/storage.conf
RUN mkdir -p /var/lib/shared/overlay-images /var/lib/shared/overlay-layers /var/lib/shared/vfs-images /var/lib/shared/vfs-layers; touch /var/lib/shared/overlay-images/images.lock; touch /var/lib/shared/overlay-layers/layers.lock; touch /var/lib/shared/vfs-images/images.lock; touch /var/lib/shared/vfs-layers/layers.lock

COPY scripts/buildah_image_analysis.sh \
scripts/skopeo_image_analysis.sh \
scripts/docker-entrypoint.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/buildah_image_analysis.sh \
&& chmod +x /usr/local/bin/skopeo_image_analysis.sh \
&& chmod +x /usr/local/bin/docker-entrypoint.sh

USER anchore:anchore

ENTRYPOINT ["docker-entrypoint.sh"]
