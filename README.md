# Observate  V2

Quickly Perform, Visualize and manage Nmap scans.

__Perform Nmap scans and output results to a file__
![Network Scan](/media/scanview.png)

__Upload Nmap XML and manage previously performed scans__
![Network Scan History](/media/history.png)

__Create network graphs easily, and quickly see which hosts have the biggest attack surface.__
![Network Scan Graph](/media/graph.png)

__View the scanned devices their potential Operating System matches, open ports and look up Vulners.com datbase for intersting entries.__
![Network Devices List](/media/Vulners.png)

__To perform Nmap scan with OS detection and service detection:__
```
Target: <your hosts> Options: -sV -O
```

## Docker Build and Deploy

```
docker build -t observatev2 .
docker run -d --name observatev2 -p 80:80 observate2

OR, For better performance in Network scans

docker run -d --name observatev2 --network=host observate2

```


## Future goals:
* Find the difference between two scans
* Ditch SocketIO for updating scan progress in favor of AJAX client side requests
* Scan all ports for Vulners database entries simultaneously
* Include support for traceroute network hops in NMAP

## Credits:
__Observate_
[Project this work is based on](https://github.com/handyscripts/Observate)

__Nmap-xml-vulners_
[Inspiration for the datbase search script](https://github.com/9p4/nmap-xml-vulners)

