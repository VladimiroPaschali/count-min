#![no_std]
#![no_main]
use aya_bpf::{
    bindings::xdp_action,
    macros::{map,xdp},
    maps::{PerCpuHashMap,PerCpuArray},
    programs::XdpContext};
use aya_log_ebpf::info;

use core::{mem, u32};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};


/*
extern crate rustc_hash;
use rustc_hash::FxHasher;
use core::hash::{Hash,Hasher};

struct CountMinSketch {
    width: u32,
    depth: u32,
    counters: [u32; 4096], 
}

impl CountMinSketch {
    fn new(width: u32, depth: u32) -> Self {
        CountMinSketch {
            width,
            depth,
            counters: [0; 4096],
        }
    }

    fn update(&mut self, key: &u32, count: u32) {
        let hash = self.custom_hash(key) as u32; //tronca hash

        for i in 0..self.depth {
            let index = (hash.wrapping_add(i)) % self.width;
            let offset = (i * self.width + index) as usize;
            self.counters[offset] = self.counters[offset].wrapping_add(count);
        }
    }

    fn estimate(&self, key: &u32) -> u32 {
        let mut min_count = u32::MAX;
        let hash = self.custom_hash(key) as u32; // tronca hash

        for i in 0..self.depth {
            let index = (hash.wrapping_add(i)) % self.width;
            let offset = (i * self.width + index) as usize;
            min_count = min_count.min(self.counters[offset]);
        }

        min_count
    }

    fn custom_hash(&self, key: &u32) -> u64 {
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        hasher.finish()
    }
} */


#[map]
static MAPPA: PerCpuHashMap<u32, u32> =
    PerCpuHashMap::<u32, u32>::with_max_entries(1024, 0);//flag 0 = none 1=by name
//static A1: PerCpuArray::<u32> = PerCpuArray::<u32>::with_max_entries(1024,0);

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

    let key_ip = (source_addr,source_port,proto,dest_addr,dest_port);
    //let point = MAPPA.get_ptr_mut(0);
    //*point+=1;
    //MAPPA.insert(&source_addr, val+=1, 0);
    //let mut cms = CountMinSketch :: new(64,4);
    let val = unsafe { MAPPA.get(&proto)};
    let prova = val.unwrap_or(&0) +1;
    let _ = MAPPA.insert(&proto, &prova, 0);

    
    //let val = unsafe {A1.get_ptr_mut(1)};
    //let prova = val.unwrap_or(0 as *mut u32);
    //unsafe { *prova+=1};
    
    
 

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
