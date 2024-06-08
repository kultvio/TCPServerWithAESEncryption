sudo apt update
sudo snap install cmake --classic
sudo apt-get update && sudo apt-get install build-essential
sudo apt-get install libssl-dev
Создайте папку build внутри папки Client или Server
cmake ..
cmake --build .
./Server ip port 
или 
./Client ip port
