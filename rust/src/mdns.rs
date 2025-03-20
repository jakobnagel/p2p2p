use gethostname::gethostname;
use local_ip_address::local_ip;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{net::IpAddr, sync::mpsc};

pub fn init_mdns(sender: mpsc::Sender<IpAddr>) -> Result<ServiceDaemon, mdns_sd::Error> {
    let mdns = ServiceDaemon::new()?;

    let receiver = init_broadcast_and_browse(&mdns)?;

    std::thread::spawn(move || {
        for event in receiver {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    for ip in info.get_addresses() {
                        sender.send(*ip).expect("pipe error");
                    }
                }
                other_event => {
                    println!("Received other event: {:?}", &other_event);
                }
            }
        }
    });

    Ok(mdns)
}

fn init_broadcast_and_browse(
    mdns: &ServiceDaemon,
) -> Result<mdns_sd::Receiver<ServiceEvent>, mdns_sd::Error> {
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

    let receiver = mdns.browse(service_type)?;

    mdns.register(my_service)?;

    Ok(receiver)
}
