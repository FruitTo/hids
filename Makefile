CC = g++
CFLAG = -O3 -lpthread -ltins -lpqxx -lpq -lcurl -std=c++17

all: install

hids:
	$(CC) src/main.cpp -o hids $(CFLAG)

install: hids
	cat src/hids_threshold.conf > /tmp/hids_ready.conf
	tail -n 4 .env >> /tmp/hids_ready.conf
	sudo mv /tmp/hids_ready.conf /etc/hids_threshold.conf
	sudo mv hids /usr/local/bin/hids
	sudo hids --network-config
	sudo cp src/hids.service /etc/systemd/system/hids.service
	sudo systemctl daemon-reload

clean:
	-sudo rm /usr/local/bin/hids
	-sudo rm /etc/hids_threshold.conf
	-sudo rm /etc/hids_network.conf
	-sudo rm /etc/systemd/system/hids.service

