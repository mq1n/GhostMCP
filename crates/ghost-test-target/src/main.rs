//! Ghost-MCP Test Target
//!
//! A dummy application with known memory layout for testing ghost-agent functionality.
//! Provides predictable addresses and behaviors for automated testing.

// Allow static_mut_refs - this is intentional for testing memory read/write
#![allow(static_mut_refs)]

use std::io::{self, Write};
use std::sync::atomic::{AtomicI32, Ordering};

// ============================================================================
// STATIC VALUES - Known addresses for testing memory read/write
// ============================================================================

#[no_mangle]
pub static mut HEALTH: i32 = 100;

#[no_mangle]
pub static mut MAX_HEALTH: i32 = 100;

#[no_mangle]
pub static mut GOLD: i32 = 500;

#[no_mangle]
pub static mut LEVEL: i32 = 1;

#[no_mangle]
pub static mut EXPERIENCE: i32 = 0;

#[no_mangle]
pub static mut PLAYER_NAME: [u8; 32] = *b"TestPlayer\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

// Pattern for AOB scanning tests: unique byte sequence
#[no_mangle]
pub static UNIQUE_PATTERN: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0x42, 0x42, 0xFF, 0x00, 0xAA, 0x55,
];

// Atomic counter for thread-safe testing
static TICK_COUNT: AtomicI32 = AtomicI32::new(0);

// ============================================================================
// EXPORTED FUNCTIONS - For hooking tests
// ============================================================================

#[no_mangle]
pub extern "C" fn take_damage(amount: i32) -> i32 {
    unsafe {
        HEALTH = (HEALTH - amount).max(0);
        println!(
            "[Game] Took {} damage! Health: {}/{}",
            amount, HEALTH, MAX_HEALTH
        );
        HEALTH
    }
}

#[no_mangle]
pub extern "C" fn heal(amount: i32) -> i32 {
    unsafe {
        HEALTH = (HEALTH + amount).min(MAX_HEALTH);
        println!(
            "[Game] Healed {}! Health: {}/{}",
            amount, HEALTH, MAX_HEALTH
        );
        HEALTH
    }
}

#[no_mangle]
pub extern "C" fn add_gold(amount: i32) -> i32 {
    unsafe {
        GOLD += amount;
        println!("[Game] Gained {} gold! Total: {}", amount, GOLD);
        GOLD
    }
}

#[no_mangle]
pub extern "C" fn spend_gold(amount: i32) -> bool {
    unsafe {
        if GOLD >= amount {
            GOLD -= amount;
            println!("[Game] Spent {} gold! Remaining: {}", amount, GOLD);
            true
        } else {
            println!("[Game] Not enough gold! Have: {}, Need: {}", GOLD, amount);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn add_experience(amount: i32) {
    unsafe {
        EXPERIENCE += amount;
        // Level up every 100 XP
        while EXPERIENCE >= 100 {
            EXPERIENCE -= 100;
            LEVEL += 1;
            MAX_HEALTH += 10;
            HEALTH = MAX_HEALTH;
            println!("[Game] LEVEL UP! Now level {}", LEVEL);
        }
        println!("[Game] Gained {} XP! Total: {}/100", amount, EXPERIENCE);
    }
}

#[no_mangle]
pub extern "C" fn get_tick_count() -> i32 {
    TICK_COUNT.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn compute_something(a: i32, b: i32, c: i32) -> i32 {
    // A function with multiple parameters for call testing
    let result = (a * b) + c;
    println!("[Game] compute_something({}, {}, {}) = {}", a, b, c, result);
    result
}

// ============================================================================
// MAIN LOOP
// ============================================================================

fn print_status() {
    unsafe {
        println!();
        println!("=== Ghost-MCP Test Target ===");
        println!("Health:     {}/{}", HEALTH, MAX_HEALTH);
        println!("Gold:       {}", GOLD);
        println!("Level:      {}", LEVEL);
        println!("Experience: {}/100", EXPERIENCE);
        println!("Ticks:      {}", TICK_COUNT.load(Ordering::SeqCst));
        println!();
        println!("Memory addresses:");
        println!("  HEALTH:         {:p}", &HEALTH);
        println!("  GOLD:           {:p}", &GOLD);
        println!("  LEVEL:          {:p}", &LEVEL);
        println!("  UNIQUE_PATTERN: {:p}", &UNIQUE_PATTERN);
        println!();
    }
}

fn print_help() {
    println!("Commands:");
    println!("  status    - Show current game state and memory addresses");
    println!("  damage N  - Take N damage");
    println!("  heal N    - Heal N health");
    println!("  gold N    - Add N gold");
    println!("  spend N   - Spend N gold");
    println!("  xp N      - Add N experience");
    println!("  reset     - Reset to initial state");
    println!("  help      - Show this help");
    println!("  quit      - Exit the program");
    println!();
}

fn reset_state() {
    unsafe {
        HEALTH = 100;
        MAX_HEALTH = 100;
        GOLD = 500;
        LEVEL = 1;
        EXPERIENCE = 0;
        TICK_COUNT.store(0, Ordering::SeqCst);
        println!("[Game] State reset!");
    }
}

fn main() {
    println!("Ghost-MCP Test Target v{}", env!("CARGO_PKG_VERSION"));
    println!("A dummy application for testing ghost-agent functionality.");
    println!();
    print_help();
    print_status();

    // Spawn tick thread
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        TICK_COUNT.fetch_add(1, Ordering::SeqCst);
    });

    // Main command loop
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "status" | "s" => print_status(),
            "help" | "h" | "?" => print_help(),
            "quit" | "exit" | "q" => break,
            "reset" | "r" => reset_state(),
            "damage" | "d" => {
                if let Some(amount) = parts.get(1).and_then(|s| s.parse().ok()) {
                    take_damage(amount);
                } else {
                    println!("Usage: damage <amount>");
                }
            }
            "heal" => {
                if let Some(amount) = parts.get(1).and_then(|s| s.parse().ok()) {
                    heal(amount);
                } else {
                    println!("Usage: heal <amount>");
                }
            }
            "gold" | "g" => {
                if let Some(amount) = parts.get(1).and_then(|s| s.parse().ok()) {
                    add_gold(amount);
                } else {
                    println!("Usage: gold <amount>");
                }
            }
            "spend" => {
                if let Some(amount) = parts.get(1).and_then(|s| s.parse().ok()) {
                    spend_gold(amount);
                } else {
                    println!("Usage: spend <amount>");
                }
            }
            "xp" | "x" => {
                if let Some(amount) = parts.get(1).and_then(|s| s.parse().ok()) {
                    add_experience(amount);
                } else {
                    println!("Usage: xp <amount>");
                }
            }
            _ => println!("Unknown command. Type 'help' for available commands."),
        }
    }

    println!("Goodbye!");
}
