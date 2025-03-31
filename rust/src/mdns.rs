use crate::state;
use gethostname::gethostname;
use local_ip_address::local_ip;
use log;
use mdns_sd::{Receiver, Result, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::Ordering,
        mpsc::{RecvTimeoutError, TryRecvError},
    },
    time::Duration,
};

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
            mdns: mdns,
            mdns_receiver,
        })
    }

    pub fn run(&self) {
        let receiver = self.mdns_receiver.to_owned();

        let local_ip = local_ip().unwrap();

        loop {
            if state::SHUTDOWN.load(Ordering::SeqCst) {
                log::info!("mDNS loop shutting down.");
                break;
            }
            match receiver.try_recv() {
                Ok(event) => match event {
                    ServiceEvent::ServiceResolved(info) => {
                        log::info!("Received info: {:?}", info);
                        let port = info.get_port();
                        for ip in info.get_addresses() {
                            log::info!("Found IP Address: {}", ip);

                            if *ip == local_ip {
                                log::info!("Skipping own IP address: {}", ip);
                                continue;
                            }

                            match ip {
                                IpAddr::V4(ipv4) => {
                                    if ipv4.octets()[0] == 192 {
                                        log::info!("Found good remote IP: {}:{}", ipv4, port);
                                        let socket_addr = SocketAddr::new(IpAddr::V4(*ipv4), port);
                                        state::init_client_data(socket_addr);
                                    } else {
                                        log::debug!("Skipping non 192 address: {}", ipv4);
                                    }
                                }
                                IpAddr::V6(ipv6) => {
                                    log::info!("Skipping IPv6 address: {}", ipv6);
                                    continue;
                                }
                            }
                        }
                    }
                    other_event => {
                        log::debug!("mDNS Received other event: {:?}", &other_event);
                    }
                },
                Err(flume::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(flume::TryRecvError::Disconnected) => {
                    eprintln!("mDNS receiver disconnected.");
                    break;
                }
            }
        }

        for event in receiver {
            if state::SHUTDOWN.load(Ordering::SeqCst) {
                self.mdns.shutdown().unwrap();
                break;
            }
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    log::info!("Received info: {:?}", info);
                    let port = info.get_port();
                    for ip in info.get_addresses() {
                        log::info!("Found IP Address: {}", ip);

                        if *ip == local_ip {
                            log::info!("Skipping own IP address: {}", ip);
                            continue;
                        }

                        match ip {
                            IpAddr::V4(ipv4) => {
                                if ipv4.octets()[0] == 192 {
                                    log::info!("Found good remote IP: {}:{}", ipv4, port);
                                    let socket_addr = SocketAddr::new(IpAddr::V4(*ipv4), port);
                                    state::init_client_data(socket_addr);
                                } else {
                                    log::debug!("Skipping non 192 address: {}", ipv4);
                                }
                            }
                            IpAddr::V6(ipv6) => {
                                log::info!("Skipping IPv6 address: {}", ipv6);
                                continue;
                            }
                        }
                    }
                }
                other_event => {
                    log::debug!("Received other event: {:?}", &other_event);
                }
            }
        }
    }
}
