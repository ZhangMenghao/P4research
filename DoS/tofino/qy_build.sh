#!/bin/bash
#2018.3 qiaoyi
#modified from wsh's script
#build synproxy program

cd $SDE/pkgsrc/p4-build-4.1.1.15
make clean
echo 'clean done!'
./configure --prefix=$SDE_INSTALL --with-tofino enable_thrift=yes P4_PATH=$SDE/synproxy/syntry.p4 P4_NAME=synproxy
make
echo 'make done!'
make install
echo 'make install done!'
sed -e "s/TOFINO_SINGLE_DEVICE/synproxy/" $SDE/pkgsrc/p4-examples-4.1.1.15/tofino_single_device.conf.in > $SDE_INSTALL/share/p4/targets/synproxy.conf
echo 'conf done!'
