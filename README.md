# Google_CSE_Simulation
NYCU Cryptographic Engineering Final Project

## Using mkcert to generate keys and certificates
### 1. download mkcert tool
```sudo apt install libnss3-tools
curl -JLO https://dl.filippo.io/mkcert/latest?for=linux/amd64
chmod +x mkcert-v*-linux-amd64
sudo mv mkcert-v*-linux-amd64 /usr/local/bin/mkcert
mkcert -install 
```

### 2. generate keys and certificates
First, cd ~/crypto_final/Google_CSE_Simulation/server
Then, use ```mkcert 127.0.0.1 localhost <your-host-only-ip>`` to generate .pem file.``` to generate certificates. (note that host-only ip should be 192.168.56.X)
For example, ```mkcert 127.0.0.1 localhost 192.168.56.103```
If you only want to test localhost, just type ```mkcert 127.0.0.1 localhost```
And you will get two .pem file, in this case is **127.0.0.1+2.pem** and **127.0.0.1+2-key.pem**
You can use ``` openssl x509 -in 127.0.0.1+2.pem -text -noout | grep DNS ``` to check if the host-only-ip and localhost ip exist or not.