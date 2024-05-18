# kavsshwsproxy - SSH via WebSocket proxy

This project was started as try to use [xterm.js](https://github.com/xtermjs/xterm.js)
in web-interface for control servers in large Enterprise network by SSH connections.
Web interface can help you simply select and use one of hundreds or thousands different
IP addresses (servers or devices) and public/private SSH keys pairs per one host or
groups. No any "Create new connection..." buttons needed.

I try use one of existing websocket proxy [wsProxy](https://github.com/herenow/wsProxy)
with telnet and make working test setup with color linux terminal. But wsProxy does not
support ssh session, and use JS and Node.

Time for turn on C power !

## Help

```
$ LD_LIBRARY_PATH=/usr/local/lib64 ./kavsshwsproxy -h
kavsshwsproxy (v0.3) SSH via WebSocket proxy
Kuzin Andrey (2024-05-12) MIT - https://github.com/KuzinAndrey/kavsshwsproxy
libevent version: "2.2.1-alpha-dev"
OpenSSL version: "OpenSSL 1.1.1k  FIPS 25 Mar 2021"
libssh2 version: "1.11.1_DEV"

Usage: ./kavsshwsproxy [options]
	-f - foreground mode (daemonize by default)
	-l <ip> - listening IP (default: "0.0.0.0")
	-p <port> - ssh port (default: 6970)
	-k - insecure HTTP mode
	-a <fullchain.pem> - fullchain SSL cert PEM file (default: "fullchain.pem")
	-b <primary> - primary SSL cert PEM file (default: "prikey.pem")
	-x <termtype> - SSH PTY terminal type (ex. xterm-color, ansi, vt100 ...)
	-d <records_dir> - path to directory with records (default: "/tmp/records")
	-s <suffix> - records file suffix (default: "sshproxyrec.gz")
```

## Prepare libraries for build

Add headers for zlib:
```shell
sudo apt install zlib1g-dev
```

Last release of libevent2 2.1.12 from 5-Jul-2020 don't include any WebSocket support yet.
We need to build locally last developer libevent version:
```shell
git clone https://github.com/libevent/libevent
cd libevent
mkdir build && cd build
cmake ..
make
sudo make install
```

Build local version of last libssh2:
```shell
git clone https://github.com/libssh2/libssh2
cd libssh2
mkdir build && cd build
cmake ..
make
sudo make install
```

Use ./build.sh to build program or something manual. Can you compile program without cmake ?

## How to use

For make new WebSocket session you need create by external application 3 control files
in `/tmp` directory with random UUIDv4 prefix and extension `.sshws`,`.pri` and `.pub`.
File `.sshws` explain ssh connection details in format:
```
[remote_server_ip]:[ssh_port]
[client_ip]
```
In `.pri` and `.pub` file store SSH encrypted private and public keys.
For example:

```shell
$ cat /tmp/51d82f41-7700-4994-ad34-fd58c7372d16.sshws
192.168.12.123:22
196.23.21.134

$ cat /tmp/51d82f41-7700-4994-ad34-fd58c7372d16.pri
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,127E23372F957102

9Uu2cdStMxRHns3ziY4VjwwmFirZFa2lLqnvVt61VRGY3ynhpaY7oNCGWLb4wzTX
3t37S5y1vgacZUbY22Re7pPAWxKf5GdYohWgYio0f042w8bk2MAJOWG2fPGk1NuH
q31Gmw1Y8COvoSyJp1XkVk0CPk7hF555aESTpEbXVEuKP9C1SgM4j1BLTxOrPAYb
.....
2tytJiNwve30JVPEyjylREpbh2jKa38hJKoG9kFSDM18qx9nNSzE21bdIgDUixXo
1vqEoNlpV74Nt9qz2YL2PnvVu27qG16ri6LG6sJBUbV13vNHvc8MRPOn9vX7EcaW
iHDp9SeuIPe4qMDqslDe5E1O6qSSS6Va0uaJruwqAiHxocKQCwBjQMfdBdK553BQ
-----END RSA PRIVATE KEY-----

$ cat /tmp/51d82f41-7700-4994-ad34-fd58c7372d16.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB......ZabTZ41reM= alex@localhost
```
After that you can create WebSocket to address:
```
wss://[proxy_ip]:6970/proxy?uuid=51d82f41-7700-4994-ad34-fd58c7372d16&user=alex&pass=superpass
```

Example HTML:
```html
<!doctype html>
<html>
<head>
<link rel="stylesheet" href="node_modules/@xterm/xterm/css/xterm.css" />
<script src="node_modules/@xterm/xterm/lib/xterm.js"></script>
<script src="node_modules/@xterm/addon-attach/lib/addon-attach.js"></script>
</head>
<body>
<div id="terminal"></div>
<script>
try {
	if (!window["WebSocket"]) throw new Error("Your browser does not support WebSockets");

	var term = null;
	var websocket = null;

	websocket = new WebSocket("wss://[proxy_ip]:6970/proxy"
		+"?uuid=51d82f41-7700-4994-ad34-fd58c7372d16"
		+"&user=alex"
		+"&pass=superpass"
	);

	if (websocket) {
		term = new Terminal();
		term.loadAddon(new AttachAddon.AttachAddon(websocket));
		term.open(document.getElementById('terminal'));
		websocket.onclose = function(evt) {
			if (term) term.dispose();
		}
	};
} catch(e) {
	alert(e);
}
</script>
</body>
</html>
```
You only need install xterm and addon in web-project directory:
```
$ npm install @xterm/xterm
$ npm install --save @xterm/addon-attach
```

Program `kavsshwsproxy` will try to make SSH connection with `192.168.12.123:22` (by public
key authentication) and check connected client IP with value `196.23.21.134`, if all is okey
it create thread for forward traffic between SSH and WebSocket, delete this control files
in `/tmp`. As man-in-middle proxy write all traffic in gzipped log file and save it in
`/tmp/51d82f41-7700-4994-ad34-fd58c7372d16.sshproxyrec.gz` after session close for further
analysis of session history. This file can be saved in storage or database by external
script or application.

## Self signed certificate for SSL

```shell
openssl req -new -x509 -nodes -days 36500 -keyout prikey.pem -out fullchain.pem
```

## Links

* https://github.com/xtermjs/xterm.js
* https://github.com/herenow/wsProxy
* https://github.com/libevent/libevent
* https://github.com/libssh2/libssh2
* https://stackoverflow.com/questions/67452144/using-xterm-js-with-addon-term-addon-attach
* https://www.tutorialspoint.com/html5/html5_websocket.htm

## TODO

We have some segfaults as usual :) It is normal %) Try to fix it.

## Author

Kuzin Andrey <kuzinandrey@yandex.ru> 2024

## License

MIT
