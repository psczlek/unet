#!/usr/bin/bash

print_progress() {
    local step=$1
    local total_steps=$2
    local percent=$(( (step * 100) / total_steps ))
    printf "\r\033[92m[%3d%%]\033[0m \033[93m%d/%d %s\033[0m\n" "$percent" "$step" "$total_steps" "$3"
}




OPTIONS=$(getopt -o hvdi -l help,virtual,dev,install -- "$@")

if [ $? -ne 0 ]; then
  echo "Use -h to see help menu"
  return
fi

eval set -- $OPTIONS

HELP=0
VIRTUAL=0
DEV=0
INSTALL=0
ITER=0
TIMES=4

while true; do
  case "$1" in
    -h|--help) HELP=1 ;;
    -v|--virtual) VIRTUAL=1; TIMES=$(($TIMES+1)) ;;
    -d|--dev)  DEV=1; TIMES=$(($TIMES+1)) ;;
    -i|--install)  INSTALL=1 ;;
    --)        shift ; break ;;
    *)         echo "\033[91merror:\033[0m unknown option: $1" ; return ;;
  esac
  shift
done

if [ $# -ne 0 ]; then
  echo "\033[91merror:\033[0m unknown option(s): $@"
  return
fi

if [ $HELP -eq 1 ]; then
    echo '\033[94m-h,  --help\033[0m\tsee this message'
    echo '\033[94m-v,  --virtual\033[0m\tuse virtual environment(default: global)'
    echo '\033[94m-d,  --dev\033[0m\tuse developing tools'
    echo '\033[94m-i,  --install\033[0m\tinstall app'
    return
fi



#
# Test for venv
#
print_progress $ITER $TIMES "Checking for venv module"
ITER=$(($ITER+1))
python3 -m venv -h > /dev/null
if [ $? -ne 0 ]; then
    printf -e "\n\033[91merror:\033[0m python3 -m venv: venv module not installed. To proceed with installation please install the venv module\n"
    return
fi

#
# Test for pip
#
print_progress $ITER $TIMES "Checking for pip module"
ITER=$(($ITER+1))
python3 -m pip -h > /dev/null
if [ $? -ne 0 ]; then
    printf -e "\n\033[91merror:\033[0m python3 -m pip: pip module not installed. To proceed with installation please install the pip module\n"
    return
fi

if [ $INSTALL -eq 1 ]; then
    if [ $VIRTUAL -eq 1 ]; then
        print_progress $ITER $TIMES "Creating virtual environment"
        ITER=$(($ITER+1))
        # create virtual environment
        python3 -m venv ~/.virtualenv/unet
        # activate virtual environment
        source ~/.virtualenv/unet/bin/activate
        echo '\n\033[93mNOTE:\033[0m \033[96mDedicated virtual environment has been created at:\033[0m \033[92m~/.virtualenv/unet\033[0m\n'
    fi
    print_progress $ITER $TIMES "Installing all dependencies"
    ITER=$(($ITER+1))
    # isntall all dependencies
    python3 -m pip install -r requirements.txt
    echo '\n\033[93mNOTE:\033[0m \033[96mAll app dependencies has been installed\033[0m\n'
    if [ $DEV -eq 1 ]; then
      print_progress $ITER $TIMES "Installing dev dependencies"
      ITER=$(($ITER+1))
      # isntall dev dependencies
      python3 -m pip install -r requirements_dev.txt
      echo '\n\033[93mNOTE:\033[0m \033[96mDeveloping dependencies has been installed\033[0m\n'
      print_progress $ITER $TIMES "Installing app for developing"
      ITER=$(($ITER+1))
      # install app
      python3 -m pip install -e .
    else
      print_progress $ITER $TIMES "Installing app"
      ITER=$(($ITER+1))
      # install app
      python3 -m pip install .
    fi
    echo '\n\033[93mNOTE:\033[0m \033[96mApp has been installed\033[0m\n'
    print_progress $ITER $TIMES "Checking for unet version"
    # Show unet's version
    unet --version
fi