mod mirror256;

use mirror256::Mirror256;
use rand::Rng;
use std::env;
use std::time::Instant;

fn random_alphanumeric_string(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| rng.sample(rand::distributions::Alphanumeric))
        .map(char::from)
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <message>", args[0]);
        std::process::exit(1);
    }

    let message = &args[1];
    println!("Message: {}", message);
    let mut hasher = Mirror256::new(Some(message), None, None, false);
    println!("Initial Digest: {}", hasher.hexdigest());

    println!("\nStarting performance test...");

    let start_time = Instant::now();
    let mut count = 0;
    let mut last_print_time = start_time;

    for i in 0..1024 {
        let digest = hasher.digest();
        //println!("{}: {}", i, hasher.hexdigest());

        let rand_str = random_alphanumeric_string(32);
        let msg = format!("This is the canary #{}. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv", i);
        hasher = Mirror256::new(Some(&msg), None, None, false);
        count += 1;

        let current_time = Instant::now();
        if current_time.duration_since(last_print_time).as_secs() >= 1 {
            let hashes_per_second = count as f64 / current_time.duration_since(start_time).as_secs_f64();
            println!("{} hashes per 10 seconds!", hashes_per_second);
            println!("Example message: {}", msg);
            println!("Example digest: {}", hasher.hexdigest());
            //println!("Example message: {}", rand_str);
            //hasher = Mirror256::new(Some(&rand_str), None, None, false);
            //println!("Example digest: {}", hasher.hexdigest());
            count = 0;
            last_print_time = current_time;
        }
    }
}
