


sudo apt update -y && sudo apt-get update -y

sudo apt install python3-dev python3-pip -y
sudo apt install gdb -y

pip3 install pwntools 
pip3 install openai

ulimit -c unlimited

sudo echo "core.%e.%p" /proc/sys/kernel/core_pattern

