use anyhow::Context;
use aya::maps::{PerCpuHashMap,PerCpuArray,Array, PerCpuValues,HashMap};
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
#[derive(Clone, Copy)]
struct CmsRow {
    row: [u32; CMS_SIZE as usize],
}
//ci sarebbe la macro in aya::bpf
unsafe impl Pod for CmsRow{}


#[derive(Clone, Copy,Default)]
pub struct Pacchetto{
    source_addr:u32,
    dest_addr: u32,
    source_port:u16,
    dest_port:u16,
    proto:u8
}
unsafe impl Pod for Pacchetto{}

fn convert_key_tuple_to_array(key_tuple: (u32, u32, u16, u16, u8)) -> [u8; 13] {
    let mut arr = [0; 13];
    // src IP
    arr[0] = (key_tuple.0 & 0xFF) as u8;
    arr[1] = (key_tuple.0 >> 8 & 0xFF) as u8;
    arr[2] = (key_tuple.0 >> 16 & 0xFF) as u8;
    arr[3] = (key_tuple.0 >> 24 & 0xFF) as u8;
    // dst IP
    arr[4] = (key_tuple.1 & 0xFF) as u8;
    arr[5] = (key_tuple.1 >> 8 & 0xFF) as u8;
    arr[6] = (key_tuple.1 >> 16 & 0xFF) as u8;
    arr[7] = (key_tuple.1 >> 24 & 0xFF) as u8;
    // src port
    arr[8] = (key_tuple.2 & 0xFF) as u8;
    arr[9] = (key_tuple.2 >> 8 & 0xFF) as u8;
    // dst port
    arr[10] = (key_tuple.3  & 0xFF) as u8;
    arr[11] = (key_tuple.3 >> 8 & 0xFF) as u8;
    // proto
    arr[12] = key_tuple.4;
    return arr;
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

    let  mut metadata: Array<_,u32> = Array::try_from(bpf.map_mut("METADATA").unwrap())?;
    metadata.set(0,CMS_ROWS,0)?;

    //mappa kernel row [CMS_SIZE]
    let mut cms_map: HashMap<_, u32, CmsRow> = HashMap::try_from(bpf.map_mut("CMS_MAP").unwrap())?;
    //inizializzo le righe lato user
    //for loop i in rows
    for i in 0..CMS_ROWS{
        let _=cms_map.insert(
            i,
            CmsRow{row:[0;CMS_SIZE as usize]},
            //PerCpuValues::try_from(vec![CmsRow{row:[0;CMS_SIZE as usize]};nr_cpus()?])?,
            0
        );
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

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


    //o usa l'ultimo pacchetto o un pacchetto passato manualmente
    //pacchetto passato manualmente
    
    // /////////let key_ip: (u32, u32, u16, u16, u8) = (source_addr,dest_addr,source_port,dest_port,proto as u8);
    // let key_ip: (u32, u32, u16, u16, u8) = (Ipv4Addr::new(202, 148, 0, 244).into(),Ipv4Addr::new(13, 183, 43, 247).into(),64643,443,6);
    // let converted_key = convert_key_tuple_to_array(key_ip);
    // print!("\n");
    // print!("Pacchetto : ");
    // print!("SRC IP: {}, SRC PORT: {}, PROTO: {}, DST IP: {}, DST PORT : {}\n", key_ip.0, key_ip.2, key_ip.4, key_ip.1, key_ip.3);




    let mut cms_map: HashMap<_, u32, CmsRow> = HashMap::try_from(bpf.map_mut("CMS_MAP").unwrap())?;

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

        //let mut thread = 0;
        let mut tot_row = 0;
        let riga = cms_map.get(&i,0)?;
        let val = riga.row[index as usize];

        // for cpu_cms in riga.iter(){
        //     let val = cpu_cms.row[index as usize];
        //     tot_row+=val;
        //     //println!("Thread n: {} value = {}",thread,val);
        //     //thread +=1;
        // }

        if val < min && val != 0{
            min = val;
        }

        print!("Row = {} Hash = {} Index = {} ValueRow = {}\n", i, hash,index, val);

    }
    
    if min ==MAX{min = 0};
    print!("Il minimo è {}\n", min);
    

    info!("Exiting...");

    Ok(())
}
