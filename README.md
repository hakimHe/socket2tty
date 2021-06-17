# socket2tty
Forwarding data: RS232/485 to/from TCP/UDP 
1.make Compile error uci.h ? Maybe try this in ubuntu:
sudo apt-get install cmake
git clone http://git.nbd.name/luci2/libubox.git libubox.git 
cd libubox.git
cmake -DBUILD_LUA=off
sudo make install
git clone https://git.openwrt.org/project/uci.git uci.git 
cd uci.git
cmake -DBUILD_LUA=off
sudo make install
vi /etc/ld.so.conf and add new line "/usr/local/lib"
sudo ldconfig
