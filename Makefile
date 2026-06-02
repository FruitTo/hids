CC = g++
CFLAG = -O3 -lpthread -ltins -lpqxx -lpq -lcurl -std=c++17

all: install

nids:
	$(CC) src/main.cpp -o nids $(CFLAG)

install: nids
	cat src/nids_threshold.conf > /tmp/nids_ready.conf
	tail -n 4 .env >> /tmp/nids_ready.conf
	sudo mv /tmp/nids_ready.conf /etc/nids_threshold.conf
	sudo mv nids /usr/local/bin/nids
	sudo nids --network-config
	sudo cp src/nids.service /etc/systemd/system/nids.service
	sudo systemctl daemon-reload

clean:
	-sudo rm /usr/local/bin/nids
	-sudo rm /etc/nids_threshold.conf
	-sudo rm /etc/nids_network.conf
	-sudo rm /etc/systemd/system/nids.service
