use rusb::{Context, UsbContext};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new()?;
    let mut dev = None;
    for d in ctx.devices()?.iter() {
        let desc = d.device_descriptor()?;
        if desc.vendor_id() == 0x10a5 && desc.product_id() == 0x9201 {
            dev = Some(d);
            break;
        }
    }

    let dev = dev.expect("Device 10a5:9201 not found");
    println!("Found device {:?}", dev);
    let handle = dev.open()?;

    if handle.kernel_driver_active(0).unwrap_or(false) {
        println!("Detaching kernel driver on interface 0");
        let _ = handle.detach_kernel_driver(0);
    }
    handle.claim_interface(0)?;
    println!("Claimed interface 0");

    let timeout = Duration::from_secs(5);

    // 1. indicate_s_state
    let ret = handle.write_control(0x40, 8, 0x0010, 0x0000, &[], timeout);
    println!("1. indicate_s_state -> {:?}", ret);

    // 2. get_state
    let mut state = [0u8; 72];
    let ret = handle.read_control(0xc0, 80, 0, 0, &mut state, timeout);
    println!(
        "2. get_state -> {:?}, version={}.{}.{}.{}",
        ret, state[0], state[1], state[2], state[3]
    );

    // 3. cmd_init
    let init_magic = [0x10, 0x2f, 0x11, 0x17];
    let ret = handle.write_control(0x40, 1, 0x0001, 0x0000, &init_magic, timeout);
    println!("3. cmd_init -> {:?}", ret);

    // 3.1 Bulk read after init
    let mut bulk_buf = [0u8; 64];
    match handle.read_bulk(0x82, &mut bulk_buf, Duration::from_millis(1000)) {
        Ok(n) => println!(
            "3.1 Read {} bytes from bulk 0x82: {:02x?}",
            n,
            &bulk_buf[..n]
        ),
        Err(e) => println!("3.1 Bulk read error: {:?}", e),
    }

    // 4. get_tls_key
    println!("4. Requesting get_tls_key...");
    let mut key_buf = vec![0u8; 1024];
    let ret = handle.read_control(0xc0, 11, 0, 0, &mut key_buf, timeout);
    println!("4. get_tls_key -> {:?}", ret);
    if let Ok(n) = ret {
        key_buf.truncate(n);
        println!(
            "Key packet length = {}, magic = {:02x?}",
            n,
            &key_buf[..std::cmp::min(28, n)]
        );
    }

    // 5. Test arming sensor: cmd_arm with 11 2f 11 17
    println!("5. Testing arm sensor (cmd_arm 0x112f1117)...");
    let arm_magic = [0x11, 0x2f, 0x11, 0x17];
    let ret = handle.write_control(0x40, 2, 0x0001, 0x0000, &arm_magic, timeout);
    println!("5. cmd_arm -> {:?}", ret);

    // 6. Test disarming sensor: cmd_arm with 12 2f 11 17
    println!("6. Testing disarm sensor (cmd_arm 0x122f1117)...");
    let disarm_magic = [0x12, 0x2f, 0x11, 0x17];
    let ret = handle.write_control(0x40, 2, 0x0001, 0x0000, &disarm_magic, timeout);
    println!("6. cmd_disarm -> {:?}", ret);

    println!("All steps finished without disconnect!");
    Ok(())
}
