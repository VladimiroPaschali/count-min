use anyhow::Context;
use aya::maps::{PerCpuHashMap,PerCpuArray,Array, PerCpuValues};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, Pod};
use aya::util::nr_cpus;
use aya_log::{BpfLogger, Ipv4Formatter};
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use xxhash_rust::const_xxh32::xxh32 as const_xxh32;
use xxhash_rust::xxh32::xxh32;
use core::u32::MAX;
use std::net::{Ipv4Addr, IpAddr};


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}
const CMS_SIZE:u32 = 1024;
const CMS_ROWS:u32 = 4;
//ci sarebbe la macro in aya::bpf
#[derive(Clone, Copy,Default)]
struct cms{
    row : u32,
    index: u32
}
unsafe impl  Pod for cms{}


#[derive(Clone, Copy,Default)]
pub struct Pacchetto{
    source_addr:u32,
    dest_addr: u32,
    source_port:u16,
    dest_port:u16,
    proto:u8
}
unsafe impl Pod for Pacchetto{}


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

    let  mut metadata: Array<_,u32> = Array::try_from(bpf.map_mut("METADATA").unwrap())?;
    metadata.set(0,CMS_ROWS,0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    //allcms = collection of cmss from each core
    //let allcms = cms_array.get(&0, 0)?;//index 0 flag 0

    //legge ultimo pkt convertito da convert_key_tuple_to_array
    let converted_key_arr: PerCpuArray<_,[u8;13]> = PerCpuArray::try_from(bpf.map_mut("CONVERTED_KEY").unwrap())?;
    let pkts = converted_key_arr.get(&0,0)?;
    let mut converted_key :[u8;13] = Default::default();

    for cpu_pkt in pkts.iter(){
        if converted_key[0]==0{
            converted_key = *cpu_pkt;
        }
    }

    //legge l'ultimo pacchetto, probabilmente lo stesso ma salvato come struct Pacchetto
    let ultimo_pkt: PerCpuArray<_,Pacchetto> = PerCpuArray::try_from(bpf.map_mut("ULTIMO_PKT").unwrap())?;
    let ultimo_pkts = ultimo_pkt.get(&0, 0)?;
    let mut pkt:Pacchetto = Default::default();

    for cpu_pkt in ultimo_pkts.iter(){
        if pkt.source_addr==0{
            pkt = *cpu_pkt;
        }
    }

    print!("\n");
    print!("Pacchetto : ");
    print!("SRC IP: {}, SRC PORT: {}, PROTO: {}, DST IP: {}, DST PORT : {}\n", Ipv4Addr::from(pkt.source_addr), pkt.source_port, pkt.proto, Ipv4Addr::from(pkt.dest_addr), pkt.dest_port);

    //mappa kernel row [CMS_SIZE]
    let mut cms_map: PerCpuHashMap<_, cms, u32> = PerCpuHashMap::try_from(bpf.map_mut("CMS_MAP").unwrap())?;

    let mut hash :u32 = 0;
    let mut index : u32 = 0;
    let mut min: u32 = MAX;
    for i in 0..CMS_ROWS{
        if i ==0{
            hash = xxh32(&converted_key,42);
        }else {
            hash = xxh32(&hash.to_ne_bytes(),42);
        }
        index = hash%CMS_SIZE;
        print!("Row = {} Hash = {} Index = {}\n", i, hash,index);

        //let mut thread = 0;
        let key  = cms{
            row:i,
            index:index
        };
        let val = cms_map.get(&key,0)?;

        for cpu_cms in val.iter(){
            
            if *cpu_cms < min && *cpu_cms != 0{
                min = *cpu_cms;
            }
            //println!("Thread n: {} value = {}",thread,val);
            //thread +=1;
        }

    }

    print!("Il minimo è {}\n", min);
    

    info!("Exiting...");

    Ok(())
}
