Systemd-Service-File
--------------------------

login to your pmacct collector server get root (sudo -i)
vim /etc/systemd/system/nfacctd-bgp01.service

    [Unit]
    Description=Netflow-BGP-Collector
    After=network-online.target
    Wants=network-online.target
    
    [Service]
    Environment=LD_LIBRARY_PATH=/usr/local/lib
    
    Type=simple
    ExecStart=/usr/local/sbin/nfacctd -f /etc/pmacct/nfacctd-bgp01.conf
    
    KillSignal=SIGTERM
    TimeoutStopSec=30
    KillMode=control-group
    PrivateTmp=true
    
    RemainAfterExit=no
    Restart=on-failure
    RestartSec=30s

    [Install]
    WantedBy=multi-user.target
    

Config-File
--------------------------
Set on the pmacct-configfile (a.e. on /etc/pmacct/nfacctd-bgp01.conf) 
the config-key daemonize to false: 
vim /etc/pmacct/nfacctd-bgp01.conf

    ...
    daemonize: false
    ...
    
Systemd-Commands
--------------------------
`systemctl daemon-reload`

`systemctl enable nfacctd-bgp01`

it will return something like: 
> Created symlink
> /etc/systemd/system/multi-user.target.wants/nfacctd-bgp01.service ->
> /etc/systemd/system/nfacctd-bgp01.service.

some other usefull systemd commands: 
`systemctl status nfacctd-bgp01`
`systemctl start nfacctd-bgp01`
`systemctl stop nfacctd-bgp01`

checkout the logmessages of your systemd service: 
`journalctl -fu nfacctd-bgp01`
 
 