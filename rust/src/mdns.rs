use gethostname::gethostname;
use local_ip_address::local_ip;
use mdns_sd::{Receiver, Result, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::mpsc,
};

pub struct Mdns {
    mdns: ServiceDaemon,
    mdns_receiver: Receiver<ServiceEvent>,
    ip_sender: mpsc::Sender<SocketAddr>,
}

impl Mdns {
    pub fn new(ip_sender: mpsc::Sender<SocketAddr>) -> Result<Self> {
        let mdns = ServiceDaemon::new()?;

        let service_type = "_ppp._tcp.local.";
        let instance_name = "rust";
        let port = 5200;
        let properties: [(&str, &str); 0] = [];

        let ip: String = local_ip().unwrap().to_string();
        let host_name: String = gethostname().into_string().unwrap();
        let full_host_name = format!("{}.local.", host_name);

        let my_service = ServiceInfo::new(
            service_type,
            instance_name,
            &full_host_name,
            &ip,
            port,
            &properties[..],
        )?;

        let mdns_receiver = mdns.browse(service_type)?;

        mdns.register(my_service)?;

        Ok(Mdns {
            mdns,
            mdns_receiver,
            ip_sender,
        })
    }

    pub fn run(&self) {
        let receiver = self.mdns_receiver.to_owned();

        for event in receiver {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let port = info.get_port();
                    for ip in info.get_addresses() {
                        let socket_addr = SocketAddr::new(*ip, port);
                        self.ip_sender.send(socket_addr).expect("pipe error");
                    }
                }
                other_event => {
                    println!("Received other event: {:?}", &other_event);
                }
            }
        }
    }

    pub fn stop(&self) {
        self.mdns.shutdown();
    }
}
