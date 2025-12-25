/// Quick test to verify observe-core is working
use observe_core::{FileSink, Pkcs11Event, Sink};

fn main() -> anyhow::Result<()> {
    println!("Testing observe-core...");

    // Create a file sink
    let sink = FileSink::new("/app/test-observe.jsonl")?;
    println!("✓ Created FileSink at /app/test-observe.jsonl");

    // Create some test events (dur_ms is f64 milliseconds)
    let event1 = Pkcs11Event::new("C_Initialize", 0).with_duration(5.2);

    let event2 = Pkcs11Event::new("C_OpenSession", 0)
        .with_slot_id(0)
        .with_session(12345)
        .with_duration(2.1);

    let event3 = Pkcs11Event::new("C_Login", 0)
        .with_session(12345)
        .with_hint("User logged in successfully")
        .with_duration(10.5);

    // Write events
    sink.write(&event1)?;
    println!("✓ Wrote C_Initialize event");

    sink.write(&event2)?;
    println!("✓ Wrote C_OpenSession event");

    sink.write(&event3)?;
    println!("✓ Wrote C_Login event");

    sink.flush()?;
    println!("✓ Flushed to disk");

    println!("\n✅ observe-core is working! Check /app/test-observe.jsonl");

    Ok(())
}
