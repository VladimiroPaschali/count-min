#![no_std]
#![no_main]
use aya_bpf::{
    bindings::{xdp_action, bpf_attach_type::BPF_MODIFY_RETURN},
    macros::{map,xdp},
    maps::{PerCpuArray,PerCpuHashMap,Array,HashMap},
    programs::XdpContext,
    bpf_printk
};
use aya_log_ebpf::info;

use core::{mem::{self, transmute}, u32, hash};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use xxhash_rust::const_xxh32::xxh32 as const_xxh32;
use xxhash_rust::xxh32::xxh32;

const CMS_SIZE:u32 = 131072;
const CMS_ROWS:u32 = 6;

#[derive(Clone, Copy)]
struct CmsRow {
    row: [u32; CMS_SIZE as usize],
}

//let key_ip: (u32, u32, u16, u16, u8) = (source_addr,dest_addr,source_port,dest_port,proto as u8);
#[derive(Clone, Copy)]
pub struct Pacchetto{
    source_addr:u32,
    dest_addr: u32,
    source_port:u16,
    dest_port:u16,
    proto:u8
}

#[map]
//the number of rows is user definable, the map can have a max of 1024 rows
static CMS_MAP: Array::<CmsRow> = Array::<CmsRow>::with_max_entries(CMS_ROWS, 0);

#[map]
static CONVERTED_KEY: PerCpuArray::<[u8;13]> = PerCpuArray::<[u8;13]>::with_max_entries(1, 0);

#[map]
static ULTIMO_PKT: PerCpuArray::<Pacchetto> = PerCpuArray::<Pacchetto>::with_max_entries(1, 0);


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


#[xdp]
pub fn count_min(ctx: XdpContext) -> u32 {
    match try_count_min(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // 
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_count_min(ctx: XdpContext) -> Result<u32, ()> {
    //pointer to the beginning of the ethhdr
    //ctx pointer to the packet
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; 

    //if not ipv4 pass and exit
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    //start packet parsing

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr: u32 = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr: u32 = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let proto : u32 =unsafe {(*ipv4hdr).proto as u32};


    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Err(()),
    };

   info!(&ctx, "SRC IP: {:i}, SRC PORT: {}, PROTO: {}, DST IP: {:i}, DST PORT : {}", source_addr, source_port, proto, dest_addr, dest_port);

    let key_ip: (u32, u32, u16, u16, u8) = (source_addr,dest_addr,source_port,dest_port,proto as u8);
    let converted_key = convert_key_tuple_to_array(key_ip);

    //end of packet parsing

    //inserisci in ultimpo pkt per leggere l'hash user side
    if let Some(arr) = CONVERTED_KEY.get_ptr_mut(0){
        unsafe{*arr=converted_key}
    }else {
        info!(&ctx,"Else CONVERTED_KEY");
    }

    if let Some(arr) = ULTIMO_PKT.get_ptr_mut(0){
        unsafe{
            (*(arr)).source_addr = source_addr;
            (*(arr)).dest_addr = dest_addr;
            (*(arr)).source_port = source_port;
            (*(arr)).dest_port=dest_port;
            (*(arr)).proto = proto as u8;
        }
    }else {
        info!(&ctx,"Else ULTIMO_PKT");
    }

    let mut hash :u32 = 0;
    let mut index : u32 = 0;

    for i in 0..CMS_ROWS {
        //info!(&ctx,"iiiiiiiiiii {}",i);
        if i == 0{
            hash = xxh32(&converted_key,42);
        }else {
            //to_ne_bytes converts from u32 to [u8]
            hash = xxh32(&hash.to_ne_bytes(), 42);
        }
        index = hash%CMS_SIZE;

        if let Some(arr) = CMS_MAP.get_ptr_mut(i) {
            unsafe {(*arr).row[index as usize] += 1}
            info!(&ctx, "Row = {} Hash = {} Index = {} Value = {} ", i, hash, index, unsafe{(*arr).row[index as usize]} )
        }else {
            info!(&ctx,"Else CMS_MAP");
        }

    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
