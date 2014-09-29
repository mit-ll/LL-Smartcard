echo "Installing pyDes..."
wget http://twhiteman.netfirms.com/pyDES/pyDes-2.0.1.zip
unzip pyDes-2.0.1.zip
rm pyDes-2.0.1.zip
cd pyDes-2.0.1
sudo python setup.py install

echo "Installing pyscard..."
sudo apt-get install python-pyscard

echo "Installing PC/SC"
sudo apt-get install pcsc-tools pcscd
