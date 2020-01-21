CUR_DIR="$(dirname "$(readlink -f ${BASH_SOURCE[0]})")"
echo $CUR_DIR
LOG_FILE=$CUR_DIR/outfile
arg1=$1

##################################################################################
# check the flavour of OS
function which_flavour()
{
        flavour=""
        grep -c -i ubuntu /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="ubuntu"
        fi
        grep -c -i "red hat" /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="rhel"
        fi
        grep -c -i fedora /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="fedora"
        fi
        grep -c -i SuSE /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="suse"
        fi
		grep -c -i centos /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="centos"
        fi
        if [ "$flavour" == "" ]; then
                echo "Unsupported linux flavor, Supported versions are ubuntu, rhel, fedora, centos and suse"
                exit 1
        else
                echo $flavour
        fi
}

function install_pkg()
{
	os_flavour=`which_flavour`
	echo "installing required packages $os_flavour ..."
	if [ $os_flavour == "ubuntu" ]
	then
		sudo -n apt-get update
		sudo -n apt-get install --force-yes -y make gcc g++ libssl-dev dos2unix
	elif [ $os_flavour == "rhel" ] || [ $os_flavour == "fedora" ] || [ $os_flavour == "centos" ]
	then
		sudo -n yum install -y make libgcc gcc-c++ openssl-devel dos2unix
	elif [ $os_flavour == "suse" ]
	then
		sudo -n zypper -n in make gcc gcc-c++ libopenssl-devel dos2unix
	fi
}
function help_instruction()
{
	echo 'Usage ./build_components.sh [Options] '
	echo ""
	echo "1. Builds the tpmextend"
	echo "2. Copies all the binaries to tcb_protection/bin"
	echo ""
	echo "Options available : "
	echo '--help'
	echo '--installpkg-only'	
}
#Make tcb_protection
function make_tpmextend()
{
	cd $CUR_DIR/tpmextend/src
	echo "Clean tpmextend"
	make clean >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
	        echo "ERROR: Could not clean tpmextend"
	        exit 1
	fi
	echo "Building tpmextend"
	make >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
	        echo "ERROR: Could not make tpmextend"
	        exit 1
	fi
}

# copy all the binaries to tcb_protection/bin
function cp_binaries()
{
	mkdir -p $CUR_DIR/tcb_protection/bin
	echo "Copying binaries to $CUR_DIR/tcb_protection/bin directory ..."
	cp $CUR_DIR/tpmextend/bin/tpmextend $CUR_DIR/tcb_protection/bin
	echo "Build completed"
}

function main()
{
	make_tpmextend
	#cp_binaries
}
if [ $# -gt 1 ]
then
	echo "extra arguments"
	help_instruction
        exit 1
elif [ $# -eq 1 ] && [ $1 == "--help" ]
then
        help_instruction
elif [ $# -eq 1 ] && [ $1 == "--installpkg-only" ]
then
        install_pkg
elif [ $# -eq 0 ]
then
	main
else
        help_instruction
        exit 1
fi
