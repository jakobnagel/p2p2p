use crate::state;
use gethostname::gethostname;
use local_ip_address::local_ip;
use log;
use mdns_sd::{Receiver, Result, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::SocketAddr;
pub struct Mdns {
    mdns: ServiceDaemon,
    mdns_receiver: Receiver<ServiceEvent>,
}

impl Mdns {
    pub fn new() -> Result<Self> {
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
        })
    }

    pub fn run(&self) {
        let receiver = self.mdns_receiver.to_owned();

        for event in receiver {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    log::debug!("Broadcasted info: {:?}", info);
                    let port = info.get_port();
                    for ip in info.get_addresses() {
                        let socket_addr = SocketAddr::new(*ip, port);
                        // let hostname: hostname
                        state::init_client_data(socket_addr);
                    }
                }
                other_event => {
                    log::debug!("Received other event: {:?}", &other_event);
                }
            }
        }
    }
}
