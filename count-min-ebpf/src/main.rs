#![no_std]
#![no_main]
use aya_bpf::{
    bindings::xdp_action,
    macros::{map,xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::{mem, u32};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};


use core::hash::{Hash, Hasher};

//non riesco a passarli dallo user side
const CMS_SIZE:u32 = 1024;
const CMS_ROWS:u32 = 4;

#[map]
static ROW1 : PerCpuArray::<u32> = PerCpuArray::<u32>::with_max_entries(CMS_SIZE, 0);
#[map]
static ROW2 : PerCpuArray::<u32> = PerCpuArray::<u32>::with_max_entries(CMS_SIZE, 0);
#[map]
static ROW3 : PerCpuArray::<u32> = PerCpuArray::<u32>::with_max_entries(CMS_SIZE, 0);
// #[map]
//static ROW4 : PerCpuArray::<u32> = PerCpuArray::<u32>::with_max_entries(CMS_SIZE, 0);

//NUMARR[0] = CMS_ROWS = 4
/*#[map]
static NUMARR: Array::<u32> = Array::<u32>::with_max_entries(1, 0);

//static  CMS_ROW_SIZE :u32 = *NUMARR.get(0).unwrap(); 
bpf_printk!(b"CMS_SIZE %d",CMS_SIZE);
*/

// #[map]
// static MAPPA: PerCpuHashMap<u32, u32> =
//     PerCpuHashMap::<u32, u32>::with_max_entries(1024, 0);//flag 0 = none 1=by name
// #[map]
// static ARRAY: PerCpuArray::<u32> = PerCpuArray::<u32>::with_max_entries(CMS_SIZE,0);
//static ARRAY: PerCpuArray::<PerCpuHashMap<u32,u32>> = PerCpuArray::<PerCpuHashMap<u32,u32>>::with_max_entries_array_of_maps(CMS_ROW_SIZE,0);

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

//djbw
fn my_hash1(string: [u8; 13]) -> u32 { 
    let mut init = 5381u32;
    let mut c: u8;

    for i in 0..13{
            c = string[i as usize];
            init = ((init << 5) + init) + (c as u32);
            //per leggere printk
            //sudo cat /sys/kernel/debug/tracing/trace_pipe
            //unsafe{bpf_printk!(b"for loop %d",i)};
    }
    return init;
}

//sdbm
fn my_hash2(string: [u8; 13]) -> u32 { 
    let mut init = 0u32;
    let mut c:u8;

    for i in 0..13{
        c = string[i as usize];
        init = (c as u32)+(init<<6)+(init<<16)-init;
    }
    return init;
}

//lose lose
fn my_hash3(string: [u8; 13]) -> u32 { 
    let mut init = 0u32;
    let mut c:u8;

    for i in 0..13{
        c = string[i as usize];
        init += c as u32;
    }
    return init;
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

fn try_count_min(ctx: XdpContext) -> Result<u32,()> {
    //pointer to the beginning of the ethhdr
    //ctx pointer to the packet
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; 

    //if not ipv4 pass and exit
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

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

    //print
    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}, PROTO: {}, DST IP: {:i}, DST PORT : {}", source_addr, source_port, proto, dest_addr, dest_port);

    let key_ip = (source_addr,dest_addr,source_port,dest_port,proto as u8);
    let converted_key = convert_key_tuple_to_array(key_ip);

    //insert into row1
    let hash = my_hash1(converted_key);
    let index = hash%CMS_SIZE;
    info!(&ctx, "Row 1: Hash = {} Index = {}",hash,index);

    let point = ROW1.get_ptr_mut(index);
    if point.is_some(){
        //info!(&ctx,"If Row 1");
        let num = point.unwrap_or(0 as *mut u32);
        unsafe{*num+=1}
        info!(&ctx, "Row 1: Num = {}",unsafe{*num});
    }else {
        info!(&ctx,"Else Row 1");
    }

    //insert into row2
    let hash = my_hash2(converted_key);
    let index = hash%CMS_SIZE;
    info!(&ctx, "Row 2: Hash = {} Index = {}",hash,index);

    let point = ROW2.get_ptr_mut(index);
    if point.is_some(){
        //info!(&ctx,"If Row 2");
        let num = point.unwrap_or(0 as *mut u32);
        unsafe{*num+=1}
        info!(&ctx, "Row 2: Num = {}",unsafe{*num});
    }else {
        info!(&ctx,"Else Row 2");
    }

    //insert into row3
    let hash = my_hash3(converted_key);
    let index = hash%CMS_SIZE;
    info!(&ctx, "Row 3: Hash = {} Index = {}",hash,index);

    let point = ROW3.get_ptr_mut(index);
    if point.is_some(){
        //info!(&ctx,"If Row 3");
        let num = point.unwrap_or(0 as *mut u32);
        unsafe{*num+=1}
        info!(&ctx, "Row 3: Num = {}",unsafe{*num});
    }else {
        info!(&ctx,"Else Row 3");
    }
       
    
 

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
