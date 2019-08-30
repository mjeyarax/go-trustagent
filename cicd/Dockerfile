#--------------------------------------------------------------------------------------------------
# Create an image for development/debugging...
# -> docker build --tag=gta-devel .
#--------------------------------------------------------------------------------------------------
# Proxy stuff...
#  docker build --tag=gta-devel --build-arg http_proxy=http://proxy-us.intel.com:911 --build-arg https_proxy=http://proxy-us.intel.com:911 .
# 
# SSH...?
#  docker build --tag=gta-devel --build-arg http_proxy=http://proxy-us.intel.com:911 --build-arg https_proxy=http://proxy-us.intel.com:911 --build-arg ssh_prv_key="$(cat ~/.ssh/id_rsa)" --build-arg ssh_pub_key="$(cat ~/.ssh/id_rsa.pub)" .
#
#  git config --global http.proxy http://proxy-us.intel.com:911
#  git config --global https.proxy http://proxy-us.intel.com:911
#  git config --global url."ssh://git@gitlab.devtools.intel.com:29418".insteadOf https://gitlab.devtools.intel.com
#  export http_proxy=http://proxy-us.intel.com:911
#  export https_proxy=http://proxy-us.intel.com:911
#  export no_proxy=127.0.0.1,localhost
#
# Create an instance that can be used to build...
#   docker run -it -v $(pwd):/docker_host gta-devel /bin/bash
#--------------------------------------------------------------------------------------------------
# T P M   S I M U L A T O R
#--------------------------------------------------------------------------------------------------
# Create an instance that runs systemd (ex. so that tpm simulator can be run)...
#   docker run --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /c/Users/kentthom/Desktop/gta_src:/docker_host -p 127.0.0.1:8446:8080/tcp gta-devel /usr/sbin/init
#
# Attach to instance using 'docker attach'...
# Start simulator: /simulator/src/tpm_server&
# systemctl enable tpm2-abrmd --> error
# systemctl start tpm2-abrmd --> error
# tpm2-abrmd --allow-root --tcti=mssim&
# tpm2_pcrlist (ok)
#--------------------------------------------------------------------------------------------------
# G I T L A B   R U N N E R
#--------------------------------------------------------------------------------------------------
# INSTALL WINDOWS
# curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh > script.rpm.sh
# chmod 700 script.rpm.sh
# ./script.rpm.sh
# yum -y install gitlab-runner
#
# RUN GITLAB-RUNNER ON WINDOWS...
# Download gitlab-runner.exe
# Start elevated command prompt
# cd to project directory
# Run 'c:\gitlab-runner\gitlab-runner.exe exec shell (compile|test)'
# ==> GONNA NEED A RUNNER WITH THIS IMAGE INSTALLED
#--------------------------------------------------------------------------------------------------
# Empty mount drive issue on Windows...
# docker volume rm -f /host_mnt/c:
# Restart docker, try again
#--------------------------------------------------------------------------------------------------
FROM fedora:29

# Authorize SSH Host
#RUN mkdir -p /root/.ssh && \
#    chmod 0700 /root/.ssh

# Add the keys and set permissions
#RUN echo "$ssh_prv_key" > /root/.ssh/id_rsa && \
#    echo "$ssh_pub_key" > /root/.ssh/id_rsa.pub && \
#    chmod 600 /root/.ssh/id_rsa && \
#    chmod 600 /root/.ssh/id_rsa.pub

ENV container docker

RUN yum -y update

RUN yum -y install systemd && yum clean all && \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;

#  Development tools: gcc 8.3.1 (rhel8), ldd v2.28
RUN yum -y group install "Development Tools" 
RUN yum -y install golang makeself

# tss2
RUN yum -y install tpm2-abrmd tpm2-tools tpm2-abrmd-devel 

# build the tpm simulator
RUN yum -y install wget openssl-devel sudo
RUN wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz \
    && mkdir simulator \
    && cd simulator \
    && tar -xavf ../ibmtpm1332.tar.gz \
    && cd src \
    && make