#!/bin/bash

check_running_user() {
    USER_RUNNING=`whoami`
    if [[ $USER_RUNNING != "root" ]] ; then
        print_error "Please run the script as root user or using sudo"
        exit 1
    fi
}

is_os_supported() {
    # example: is_os_supported "Oracle Enterprise Linux release" ORACLE_REL ORACLE_RELS
    NAME=$1
    CURRENT_REL=$2
    ALL_RELS=$3
    if [[ $ALL_RELS =~ (^|[[:space:]])"$CURRENT_REL"($|[[:space:]]) ]] ; then
        print_info "The operating system is $NAME $CURRENT_REL"
    else
        print_warning "The operating system might not be supported"
    fi
}

is_kernel_supported() {
    CURRENT_KERNEL=$1
    SUPPORTED_KERNELS=$2
    KERS=($(echo $SUPPORTED_KERNELS | tr " " "\n"))
    SUPPORTED=false
    for k in "${KERS[@]}"
    do
        if [[ $CURRENT_KERNEL =~ $k ]] ; then
          SUPPORTED=true
        fi
    done
    if [ $SUPPORTED = true ] ; then
        print_info "The kernel version is $CURRENT_KERNEL"
    else
        print_error "The kernel version $CURRENT_KERNEL is not supported"
    fi
}

check_os() {
    ORACLE_OS_RELEASE=/etc/oracle-release
    SUSE_OS_RELEASE=/etc/SuSE-release
    UBUNTU_OS_RELEASE=/etc/lsb-release
    grep "Ubuntu" /etc/lsb-release >> /dev/null 2>&1
    IS_UBUNTU=$?
    DEBIAN_OS_RELEASE=/etc/debian_version
    CENTOS_OS_RELEASE=/etc/centos-release
    FEDORA_OS_RELEASE=/etc/fedora-release
    REDHAT_OS_RELEASE=/etc/redhat-release
    grep "Red Hat" /etc/redhat-release >> /dev/null 2>&1
    IS_REDHAT=$?
    grep "Amazon Linux 2" /etc/os-release >> /dev/null 2>&1
    IS_AMZN2=$?
    KER_VERSION=`cat /proc/version | awk '{print $3}'`
    # ORACLE
    if [[ -f $ORACLE_OS_RELEASE ]] ; then
        ORACLE_REL=`cat $ORACLE_OS_RELEASE | awk '{ print $5 }'`
        ORACLE_RELS="5.10 5.11 6.1 6.2 6.3 6.4 6.5 6.6 6.7 6.8 6.9 6.10 7.0 7.1 7.2 7.3 7.4 7.5 7.6"
        is_os_supported "Oracle Enterprise Linux release" "$ORACLE_REL" "$ORACLE_RELS"
        ORACLE_KERS="2.6.39-400.[0-9].*.el5uek 2.6.32-100.[0-9].*.el6uek.x86_64 2.6.32-300.[0-9].*.el6uek.x86_64 2.6.39-200.[0-9].*.el6uek.x86_64 2.6.39-400.[0-9].*.el6uek.x86_64 3.8.13-[0-9].*.el6uek.x86_64 3.8.13-[0-9].*.el7uek.x86_64 3.8.13-35.[0-9].*.el7uek.x86_64 3.8.13-55.[0-9].*.el7uek.x86_64 4.1.12-[0-9].*.el6uek.x86_64 4.1.12-[0-9].*.el7uek.x86_64 4.14.35-[0-9].*.el7uek.x86_64 5.4.17-[0-9].*.el7uek.x86_64"
        is_kernel_supported "$KER_VERSION" "$ORACLE_KERS"
    # SUSE
    elif [[ -f $SUSE_OS_RELEASE ]] ; then
        SUSE_VERSION=`grep VERSION $SUSE_OS_RELEASE | awk '{ print $3 }'`
        SUSE_VERSIONS="11 12 15"
        is_os_supported "SUSE Linux Enterprise Server" "$SUSE_VERSION" "$SUSE_VERSIONS"
        SUSE_KERS="2.6.32.12-0.7-default 3.0.13-0.27-default 3.0.76-0.11-default 3.0.101-*.*-default 3.12.*-default 4.4.*-default 4.12.*-default 5.3.*-default 5.14.*-default"
        is_kernel_supported "$KER_VERSION" "$SUSE_KERS"
        print_info "Note: Migrated SUSE Linux Enterprise Server VMs must use SUSE Public Cloud Program (BYOS) licenses"
    # UBUNTU
    elif [[ -f $UBUNTU_OS_RELEASE ]] && [[ $IS_UBUNTU -eq 0 ]] ; then
        UBUNTU_REL=`grep DISTRIB_RELEASE $UBUNTU_OS_RELEASE | awk -F "=" '{ print $2 }'`
        UBUNTU_RELS="12.04 12.10 13.04 13.10 14.04 14.10 15.04 16.04 16.10 17.04 18.04 20.04 22.04"
        is_os_supported "Ubuntu" "$UBUNTU_REL" "$UBUNTU_RELS"
        UBUNTU_KELS="3.2.0-[0-9].*-generic 3.2.0-[0-9].*-virtual 3.5.0-[0-9].*-generic 3.8.0-[0-9].*-generic 3.11.0-[0-9].*-generic 3.13.0-[0-9].*-generic 3.16.0.[0-9].*-generic 3.16.0-[0-9].*-amd64 3.19.0.[0-9].*-generic 4.2.0-[0-9].*-generic 4.4.0-[0-9].*-generic 4.8.0-[0-9].*-generic 5.4.0-[0-9].*-generic 4.10.0-[0-9].*-generic 4.15.0-[0-9].*-generic 5.15.0-[0-9].*-generic"
        is_kernel_supported "$KER_VERSION" "$UBUNTU_KELS"
    # DEBIAN
    elif [[ -f $DEBIAN_OS_RELEASE ]] ; then
        DEBIAN_REL=`cat $DEBIAN_OS_RELEASE`
        DEBIAN_RELS="6.0.0 6.0.1 6.0.2 6.0.3 6.0.4 6.0.5 6.0.6 6.0.7 6.0.8 7.0 7.1 7.2 7.3 7.4 7.5 7.6 7.7 7.8"
        is_os_supported "Debian" "$DEBIAN_REL" "$DEBIAN_RELS"
        DEBIAN_KELS="2.6.32-[0-9].*-amd64 2.6.32-[0-9].*-686 2.6.32-[0-9].*-686-bigmem 3.2.0-[0-9].*-amd64 3.2.0-[0-9].*-686-pae 4.19.0-[0-9].*-amd64 5.10.0-[0-9].*-amd64"
        is_kernel_supported "$KER_VERSION" "$DEBIAN_KELS"
    # CENTOS
    elif [[ -f $CENTOS_OS_RELEASE ]] ; then
        CENTOS_REL=`grep CentOS $CENTOS_OS_RELEASE | sed 's/[^0-9.]//g' | awk -F "." '{ print $1"."$2 }'`
        CENTOS_RELS="5.1 5.2 5.3 5.4 5.5 5.6 5.7 5.8 5.9 5.10 5.11 6.1 6.2 6.3 6.4 6.5 6.6 6.7 6.8 7.0 7.1 7.2 7.3 7.4 7.5 7.6 7.7 7.8 7.9 8.0 8.1 8.2"
        is_os_supported "CentOS" "$CENTOS_REL" "$CENTOS_RELS"
        CENTOS_KELS="2.6.32-[0-9].*.el6.x86_64 2.6.32-[0-9].*.el6 2.6.18-[0-9].*.el5.x86_64 2.6.18-[0-9].*.el5 3.10.0-[0-9].*.el7(.*).x86_64 4.19.27-1.el7.x86_64"
        is_kernel_supported "$KER_VERSION" "$CENTOS_KELS"
    # FEDORA
    elif [[ -f $FEDORA_OS_RELEASE ]] ; then
        FEDORA_REL=`grep Fedora $FEDORA_OS_RELEASE | sed 's/[^0-9]//g'`
        FEDORA_RELS="18 19 20 21"
        is_os_supported "Fedora" "$FEDORA_REL" "$FEDORA_RELS"
        FEDORA_KELS="3.2.5-[0-9]+.fc18.x86_64 3.9.5-[0-9]+.fc19.x86_64 3.11.10-[0-9]+.fc20.x86_64 3.19.4-[0-9]+.fc21.x86_64"
        is_kernel_supported "$KER_VERSION" "$FEDORA_KELS"
    # REDHAT
    elif [[ -f $REDHAT_OS_RELEASE ]] && [[ $IS_REDHAT -eq 0 ]] ; then
        REDHAT_REL=`grep Red $REDHAT_OS_RELEASE | sed 's/[^0-9.]//g' | awk -F "." '{ print $1"."$2 }'`
        REDHAT_RELS="5.1 5.2 5.3 5.4 5.5 5.6 5.7 5.8 5.9 5.10 5.11 6.1 6.2 6.3 6.4 6.5 6.6 6.7 6.8 6.9 7.0 7.1 7.2 7.3 7.4 7.5 7.6 7.7 7.8 7.9 8.0 8.1 8.2 8.3 8.4 8.5 8.6"
        is_os_supported "Ubuntu" "$REDHAT_REL" "$REDHAT_RELS"
        REDHAT_KELS="2.6.32-[0-9].*.el6.x86_64 2.6.32-[0-9].*.el6 2.6.18-[0-9].*.el5.x86_64 2.6.18-[0-9].*.el5 3.10.0-[0-9].*.el7(.*).x86_64 4.19.27-1.el7.x86_64 4.18.0-[0-9].*.el8(.*).x86_64"
        is_kernel_supported "$KER_VERSION" "$REDHAT_KELS"
        print_info "Note: Migrated Red Hat Enterprise Linux (RHEL) VMs must use Cloud Access (BYOS) licenses"
    # Amazon Linux 2
    elif [[ $IS_AMZN2 -eq 0 ]] ; then
        print_info "The operating system is Amazon Linux 2"
        AMZN2_KERS="4.14.[0-9]+-[0-9]+.[0-9]+.amzn2.x86_64 4.19.[0-9]+-[0-9]+.[0-9]+.amzn2.x86_64 5.4.[0-9]+-[0-9]+.[0-9]+.amzn2.x86_64 5.10.[0-9]+-[0-9]+.[0-9]+.amzn2.x86_64"
        is_kernel_supported "$KER_VERSION" "$AMZN2_KERS"
    # NOT SUPPORTED
    else
        print_error "The operating system is not supported"
    fi
}

check_grub() {
    GRUB_ROOT_DEVICE=$(sudo cat /proc/cmdline 2>/dev/null | awk 'match($0, /root=.*/) { print substr($0, RSTART, RLENGTH) }' | awk '{print $1}')
    if [[ $(echo ${GRUB_ROOT_DEVICE} | awk -F'=' '{print NF}') == 3 ]]; then
        DEV_DEF=$(echo ${GRUB_ROOT_DEVICE} | awk -F'=' {'print $3'})
        print_info "The currently active root volume is defined by LABEL or UUID: ${DEV_DEF} which is a good practice for imports"
    elif [[ $(echo ${GRUB_ROOT_DEVICE} | awk -F'=' '{print NF}') == 2 ]]; then
        DEV_DEF=$(echo ${GRUB_ROOT_DEVICE} | awk -F'=' {'print $2'})
        print_warning "The current kernel boot command is referencing the root volume using block device IDs. In some cases, this can cause issues with the import process. We recommend using the UUID instead where possible"
    fi

    VERSION=`dmesg | grep "Linux version" | awk '{print $5}'`
    FOUND_BOOT_IMAGE=`ls /boot|grep $VERSION >> /dev/null 2>&1;echo $?`
    if [[ FOUND_BOOT_IMAGE -eq 0 ]] ; then
        print_info "Found boot image in /boot"
    else
        print_error "Boot image not found or it is zero byte"
    fi
}

check_disk() {
      uname -a|grep 'arm64\|aarch64' > /dev/null 2>&1
      OS_ARM_64=$?
      if [[ $OS_ARM_64 -eq 0 ]] ; then
          print_error  "The kernel architecture is not supported"
      fi

    # For UEFI, BOOTX64.EFI file is required
    if [[ -d /boot/efi ]] ; then
        if [[ -f /boot/efi/EFI/BOOT/BOOTX64.EFI ]]; then
            print_info "Found BOOTX64.EFI file"
        else
            print_error "BOOTX64.EFI file is missing for UEFI boot"
        fi
    fi

    # Only one boot partition is allowed
    NUM_BOOT_PARTITIONS=`df -k /boot |grep "/$"| wc -l`
    if [[ $NUM_BOOT_PARTITIONS -gt 1 ]] ; then
        print_error "Only one boot partition is allowed, found $NUM_BOOT_PARTITIONS"
    fi

    # Boot partition needs to be in the root disk
    FIRST_DISK=`parted -ls 2>/dev/null| grep -m1 Disk | awk '{print $2}' | tr -d ':'`
    ROOT_PARTITION=`df -k /boot 2>/dev/null|grep "/$\|/boot$"|awk '{ print $1}'`
    IN_DISK=`fdisk -l $FIRST_DISK | grep -w $ROOT_PARTITION >> /dev/null 2>&1; echo $?`
    if [[ $IN_DISK -ne 0 ]]; then
        print_error "Root partition not found in the $FIRST_DISK"
    fi

    # Check if root disk is used by LVM
    LVM_FOUND=`lsblk $FIRST_DISK | grep lvm >> /dev/null; echo $?`
    if [[ $LVM_FOUND == 0 ]] ; then
        print_warning "Found disk $FIRST_DISK used by logical volume(s)"
    fi

    ROOT_DISK_SIZE=`fdisk -l 2>/dev/null|grep -m1 Disk|awk '{print $5}'`
    if [[ $ROOT_DISK_SIZE -lt 8796093022208 ]] ; then
        print_info  "The root volume disk size is less than 8TB"
    else
        print_error "The root volume disk size is more than 8TB"
    fi
}

check_fs() {
    SUPPORTED_FS_TYPE="ext2 ext3 ext4 btrfs jfs xfs"
    ROOT_FS_TYPE=$(df -T / | tail -1 | awk '{print $2}')

    if [[ $SUPPORTED_FS_TYPE =~ (^|[[:space:]])"$ROOT_FS_TYPE"($|[[:space:]]) ]] ; then
        print_info "The file system type is $ROOT_FS_TYPE"
    else
        print_error "The file system type is not supported"
    fi

    if [[ ${ROOT_FS_TYPE} == "ext"*  ]]; then
        FS_CHECK_DATE=$(tune2fs -l $(mount | grep 'on / ' | awk '{print $1}') | grep 'Last checked' | awk 'match($0, /Sat.*|Sun.*|Mon.*|Tue.*|Wed.*|Thu.*|Fri.*/) { print substr($0, RSTART, RLENGTH) }')
        FS_SHORT_DATE=$(date -d "${FS_CHECK_DATE}" +%s)
        CURR_SHORT_DATE=$(date +%s)
        DATEDIFF=$(echo \(${CURR_SHORT_DATE}-${FS_SHORT_DATE}\)/60/60/24 | bc 2>/dev/null)
        if [[ "${DATEDIFF}" -gt 15 ]]; then
            print_warning "Your EXT root filesystem has not been checked in more than 2 weeks - please run fsck before importing your VM"
        fi
    fi

    # Confirm driver space requirements and update this correspondingly
    MIN_SPACE=256000
    ROOT_FS_SPACE_AVAIL=`df -k / |grep "/$"|awk '{ print $4}'`
    if [[ $ROOT_FS_SPACE_AVAIL == *"%" ]]; then
        ROOT_FS_SPACE_AVAIL=`df -k / |grep "/$"|awk '{ print $3}'`
    fi
    BOOT_FS_SPACE_AVAIL=`df -k /boot|grep "/$" |awk '{ print $4}'`
    if [[ $BOOT_FS_SPACE_AVAIL == *"%" ]]; then
        BOOT_FS_SPACE_AVAIL=`df -k /boot |grep "/$"|awk '{ print $3}'`
    fi
    ETC_FS_SPACE_AVAIL=`df -k /etc|grep "/$" |awk '{ print $4}'`
    if [[ $ETC_FS_SPACE_AVAIL == *"%" ]]; then
        ETC_FS_SPACE_AVAIL=`df -k /etc |grep "/$"|awk '{ print $3}'`
    fi
    TMP_FS_SPACE_AVAIL=`df -k /tmp|grep "/$" |awk '{ print $4}'`
    if [[ $TMP_FS_SPACE_AVAIL == *"%" ]]; then
        TMP_FS_SPACE_AVAIL=`df -k /tmp |grep "/$"|awk '{ print $3}'`
    fi
    VAR_FS_SPACE_AVAIL=`df -k /var|grep "/$" |awk '{ print $4}'`
    if [[ $VAR_FS_SPACE_AVAIL == *"%" ]]; then
        VAR_FS_SPACE_AVAIL=`df -k /var |grep "/$"|awk '{ print $3}'`
    fi
    USR_FS_SPACE_AVAIL=`df -k /usr|grep "/$" |awk '{ print $4}'`
    if [[ $USR_FS_SPACE_AVAIL == *"%" ]]; then
        USR_FS_SPACE_AVAIL=`df -k /usr |grep "/$"|awk '{ print $3}'`
    fi
    if [[ $ROOT_FS_SPACE_AVAIL -gt $MIN_SPACE ]] && [[ $BOOT_FS_SPACE_AVAIL -gt $MIN_SPACE ]] && [[ $ETC_FS_SPACE_AVAIL -gt $MIN_SPACE ]] && [[ $TMP_FS_SPACE_AVAIL -gt $MIN_SPACE ]] && [[ $VAR_FS_SPACE_AVAIL -gt $MIN_SPACE ]] && [[ $USR_FS_SPACE_AVAIL -gt $MIN_SPACE ]] ; then
        print_info  "There is enough space to install EC2 drivers"
    else
        print_error "At least 250MB of space available is needed to install the EC2 drivers"
    fi

    NUM_DISKS=`lsblk 2>/dev/null| grep disk | wc -l`
    if [[ $NUM_DISKS -gt 21 ]] ; then
        print_error "Number of disk is greater than 21"
    fi
}

check_fstab() {
    root_dev=$(mount | grep 'on / ' | awk '{print $1}')
    root_uuid=$(blkid 2>/dev/null| grep ${root_dev} | grep -ow 'UUID=\S*' | sed s/\"//g)
    root_label=$(blkid 2>/dev/null| grep ${root_dev} | grep -ow 'LABEL=\S*' | sed s/\"//g)

    for block_dev in $(grep '/dev' /etc/fstab | awk '{print $1}' | sed s/\"//g)
    do
        if  [[ "${block_dev}" == "${root_dev}" ]]; then
            true
        else
            secondary_dev_array+=" ${block_dev}"
        fi
    done

    for block_label in $(grep '^LABEL' /etc/fstab | awk '{print $1}' | sed s/\"//g)
    do
        if  [[ "${block_label}" == "${root_label}" ]]; then
            true
        else
            secondary_label_array+=" ${block_label}"
        fi
    done

    for block_uuid in $(grep '^UUID' /etc/fstab | awk '{print $1}' | sed s/\"//g)
    do
        if  [[ "${block_uuid}" == "${root_uuid}" ]]; then
            true
        else
            secondary_uuid_array+=" ${block_uuid}"
        fi
    done

    if [[ -n ${secondary_dev_array} ]]; then
        for dev in ${secondary_dev_array[@]}
        do
            print_warning "Secondary volume configured in /etc/fstab for this VM: ${dev} - please ensure they are included in the import definition or comment them out of the fstab when preparing the VM for import"
        done
    fi

    if [[ -n ${secondary_label_array} ]]; then
        for dev in ${secondary_label_array[@]}
        do
            print_warning "Secondary volume configured in /etc/fstab for this VM: ${dev} - please ensure they are included in the import definition or comment them out of the fstab when preparing the VM for import"
        done
    fi

    if [[ -n ${secondary_uuid_array} ]]; then
        for dev in ${secondary_uuid_array[@]}
        do
            print_warning "Secondary volume configured in /etc/fstab for this VM: ${dev} - please ensure they are included in the import definition or comment them out of the fstab when preparing the VM for import"
        done
    fi

    if [[ -z ${secondary_label_array} && -z  ${secondary_label_array} && -z ${secondary_uuid_array} ]]; then
        print_info "Only the root volume is defined in /etc/fstab"
    fi
}

check_network() {
    DHCLIENT_RC=`pidof dhclient >> /dev/null ; echo $?`
    #SLES using wickedd instead of dhclient
    WICKEDD_RC=`pidof wickedd-dhcp4 >> /dev/null ; echo $?`
    #if grep match "0.0.0.0:68 " and the return code is 0 means that dhclient is listening
    DHCLIENT_NETSTAT=`netstat -na 2>/dev/null|grep -i '0.0.0.0:68 ' >> /dev/null; echo $?`
    if [[ $DHCLIENT_RC == 0 || $WICKEDD_RC == 0 ]] && [[ $DHCLIENT_NETSTAT == 0 ]] ; then
        print_info "DHCP client is running"
    else
        print_warning "DHCP might be disabled"
    fi

    SSH_RUNNING=`ps aux|grep sshd|grep -v grep`
    IS_SSH_RUNNING=$?
    if [[ $IS_SSH_RUNNING -eq 0 ]] ; then
        print_info "The SSH daemon is up and running"
    else
        print_warning "SSH daemon is not running"
    fi

    IPTABLES_DROP=`iptables -L |grep -i 'drop\|reject'`
    IS_IPTABLES_DROP=$?
    if [[ $IS_IPTABLES_DROP -eq 0 ]] ; then
        print_warning "Found drop/reject in the iptables rules, Check iptables doesn't block SSH before you start the conversion"
    else
        print_info "Not found any drop in the iptables"
    fi

    IPS=`ip addr | grep inet | wc -l`
    if [[ $IPS -eq 0 ]] ; then
        print_warning "IP address not assigned, please make sure TCP/IP is enabled"
    fi
}

check_vm() {
    SELINUX=`getenforce 2>/dev/null`
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 0 && $SELINUX == "Enforced" ]] ; then
        print_warning "SELinux is set to Enforced"
    fi

    CDROM_PRESENT=`dmesg | grep cdrom`
    IS_CDROM_PRESENT=$?
    CDRW_PRESENT=`dmesg | grep cd/rw`
    IS_CDRW_PRESENT=$?
    DVD_PRESENT=`dmesg | grep dvd`
    IS_DVD_PRESENT=$?
    WRITER_PRESENT=`dmesg | grep writer`
    IS_WRITER_PRESENT=$?
    if [[ $IS_CDROM_PRESENT -eq 0 ]] || [[ $IS_CDRW_PRESENT -eq 0 ]] || [[ $IS_DVD_PRESENT -eq 0 ]] || [[ $IS_WRITER_PRESENT -eq 0 ]] ; then
        print_warning "CD-ROM or DVD device detected"
    else
        print_info "No CD-ROM or DVD device detected"
    fi
}

print_info() {
    MSG=$1
    echo -e "[OK] $MSG"
}

print_warning() {
    MSG=$1
    echo -e "[WARNING] $MSG"
}

print_error() {
    MSG=$1
    echo -e "[ERROR] $MSG"
    succeeded=0
}

succeeded=1

check_running_user
check_os
check_disk
check_grub
check_fs
check_fstab
check_network
check_vm

if [[ $succeeded -eq 0 ]] ; then
    echo -e "Validation failed!"
    exit 1
else
    echo -e "Validation succeeded!"
    exit 0
fi