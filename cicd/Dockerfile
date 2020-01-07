#--------------------------------------------------------------------------------------------------
# G T A - D E V E L
#--------------------------------------------------------------------------------------------------
# This docker image is used for building tpmprovider as well as for gitlab pipelines.  It uses
# Fedora 29 with development tools, tpm simulator, etc. 
#--------------------------------------------------------------------------------------------------
# To create the 'gta-devel' image, cd to the directory with the Dockerfile and run...
#  > docker build --tag=gta-devel --build-arg http_proxy=<proxy> --build-arg https_proxy=<proxy> .
#--------------------------------------------------------------------------------------------------
# T P M   S I M U L A T O R
#--------------------------------------------------------------------------------------------------
# Create an instance of gta-devel that runs systemd so that tpm simulator can be started.
#  > docker run --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v $(pwd):/docker_host -p 9443:1443 gta-devel /usr/sbin/init
#  > /simulator/src/tpm_server -rm&
#  > systemctl start tpm2-abrmd
#--------------------------------------------------------------------------------------------------
FROM fedora:29

ENV container docker
ENV http_proxy http://proxy-us.intel.com:911
ENV https_proxy http://proxy-us.intel.com:911

RUN yum -y update

# this is needed so that the docker can run systemd and host the tpm simulator process
RUN yum -y install systemd && yum clean all && \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;

#  Development tools: gcc 8.3.1, ldd v2.28
RUN yum -y group install "Development Tools" 
RUN yum -y install golang makeself gdb vim-common

# go-trust-agent dependencies
RUN yum -y install dmidecode redhat-lsb tboot compat-openssl10 tpm2-abrmd tpm2-tools tpm2-abrmd-devel

# build the tpm simulator
RUN yum -y install wget openssl-devel sudo
RUN wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz \
    && mkdir simulator \
    && cd simulator \
    && tar -xavf ../ibmtpm1332.tar.gz \
    && cd src \
    && make

# update tpm2-abrmd.service to use the simulator (add --tcti=mssim parameter)
RUN sed -i 's|ExecStart=/usr/sbin/tpm2-abrmd|ExecStart=/usr/sbin/tpm2-abrmd --tcti=mssim|g' /usr/lib/systemd/system/tpm2-abrmd.service