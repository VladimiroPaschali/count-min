use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{PerCpuHashMap,PerCpuArray},
    programs::{Xdp, XdpFlags},
    Bpf
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/count-min"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/count-min"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("count_min").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    //reference alle mappe kernel
    let mappa: PerCpuHashMap<_, u32, u32> = PerCpuHashMap::try_from(bpf.map_mut("MAPPA").unwrap())?;
    //let a1: PerCpuArray<_,u32> = PerCpuArray::try_from(bpf.map_mut("A1").unwrap())?;
    

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    
    //stampa i valori di ogni mappa.get(6)
    const PROTO: u32 = 6;
    let proto =  mappa.get(&PROTO, 0)?;
    let mut thread = 0;
    let mut tot = 0;
    for proto in proto.iter() {
        println!("Thread {} ha letto {} pacchetti", thread, proto);
        thread+=1;
        tot+=proto;
    }
    print!("Totale pacchetti con protocollo {} = {}\n",PROTO,tot);
    //definizione va fatta dopo la fine del primo mut (hashmap)
    /*let a1: PerCpuArray<_,u32> = PerCpuArray::try_from(bpf.map_mut("A1").unwrap())?;

    //stampa da array a1
    
    let nr_cpus= nr_cpus()?;
    let val = a1.get(&0,0)?;//index 0 flag 0
    for cpu_val in val.iter() {
        print!("{}",cpu_val)
    }
    */
    

    info!("Exiting...");

    Ok(())
}
