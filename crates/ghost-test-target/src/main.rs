//! Ghost-MCP Test Target
//!
//! A dummy application with known memory layout for testing ghost-agent functionality.
//! Provides predictable addresses and behaviors for automated testing.
//!
//! Features:
//! - Static values for memory read/write tests
//! - Pointer chains for pointer scanning tests
//! - Dynamic allocations for heap scanning
//! - Functions for hooking/patching tests

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
// POINTER CHAIN STRUCTURES - For pointer scanning tests
// ============================================================================

/// Player stats structure (level 3 - deepest)
#[repr(C)]
pub struct PlayerStats {
    pub health: i32,
    pub max_health: i32,
    pub mana: i32,
    pub max_mana: i32,
    pub stamina: i32,
    pub defence: i32,
    pub attack: i32,
    pub speed: i32,
}

/// Player data structure (level 2)
#[repr(C)]
pub struct PlayerData {
    pub stats: *mut PlayerStats,
    pub gold: i32,
    pub level: i32,
    pub experience: i32,
    pub name: [u8; 32],
}

/// Game state structure (level 1)
#[repr(C)]
pub struct GameState {
    pub player: *mut PlayerData,
    pub enemy_count: i32,
    pub is_paused: bool,
    pub difficulty: i32,
}

/// Root game object (level 0 - static pointer)
#[no_mangle]
pub static mut GAME_STATE_PTR: *mut GameState = std::ptr::null_mut();

// Global storage for heap allocations
static mut PLAYER_STATS_BOX: Option<Box<PlayerStats>> = None;
static mut PLAYER_DATA_BOX: Option<Box<PlayerData>> = None;
static mut GAME_STATE_BOX: Option<Box<GameState>> = None;

// ============================================================================
// SCAN TEST VALUES - Multiple values for iterative scanning
// ============================================================================

#[no_mangle]
pub static mut SCAN_VALUE_A: i32 = 12345;

#[no_mangle]
pub static mut SCAN_VALUE_B: i32 = 12345; // Same initial value as A

#[no_mangle]
pub static mut SCAN_VALUE_C: i32 = 12345; // Same initial value

#[no_mangle]
pub static mut SCAN_FLOAT: f32 = 3.14160;

#[no_mangle]
pub static mut SCAN_DOUBLE: f64 = 2.71830000000;

// ============================================================================
// POINTER CHAIN INITIALIZATION
// ============================================================================

/// Initialize the pointer chain structures
fn init_pointer_chain() {
    unsafe {
        // Create the deepest level first (PlayerStats)
        let stats = Box::new(PlayerStats {
            health: 100,
            max_health: 100,
            mana: 50,
            max_mana: 50,
            stamina: 100,
            defence: 25,
            attack: 30,
            speed: 15,
        });
        PLAYER_STATS_BOX = Some(stats);
        let stats_ptr = PLAYER_STATS_BOX.as_mut().unwrap().as_mut() as *mut PlayerStats;

        // Create PlayerData pointing to PlayerStats
        let player = Box::new(PlayerData {
            stats: stats_ptr,
            gold: 1000,
            level: 5,
            experience: 75,
            name: *b"PointerTestPlayer\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        });
        PLAYER_DATA_BOX = Some(player);
        let player_ptr = PLAYER_DATA_BOX.as_mut().unwrap().as_mut() as *mut PlayerData;

        // Create GameState pointing to PlayerData
        let game = Box::new(GameState {
            player: player_ptr,
            enemy_count: 3,
            is_paused: false,
            difficulty: 2,
        });
        GAME_STATE_BOX = Some(game);
        GAME_STATE_PTR = GAME_STATE_BOX.as_mut().unwrap().as_mut() as *mut GameState;

        println!("[Init] Pointer chain initialized!");
    }
}

/// Get player stats through the pointer chain
fn get_player_stats() -> Option<&'static mut PlayerStats> {
    unsafe {
        if GAME_STATE_PTR.is_null() {
            return None;
        }
        let game = &mut *GAME_STATE_PTR;
        if game.player.is_null() {
            return None;
        }
        let player = &mut *game.player;
        if player.stats.is_null() {
            return None;
        }
        Some(&mut *player.stats)
    }
}

/// Get player data through the pointer chain
fn get_player_data() -> Option<&'static mut PlayerData> {
    unsafe {
        if GAME_STATE_PTR.is_null() {
            return None;
        }
        let game = &mut *GAME_STATE_PTR;
        if game.player.is_null() {
            return None;
        }
        Some(&mut *game.player)
    }
}

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
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║              Ghost-MCP Interactive Test Target               ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ STATIC VALUES (for basic read/write/scan tests)              ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!(
            "║ Health:     {:>6}/{:<6}  @ {:p}",
            HEALTH, MAX_HEALTH, &HEALTH
        );
        println!("║ Gold:       {:>6}         @ {:p}", GOLD, &GOLD);
        println!("║ Level:      {:>6}         @ {:p}", LEVEL, &LEVEL);
        println!(
            "║ Experience: {:>6}/100     @ {:p}",
            EXPERIENCE, &EXPERIENCE
        );
        println!("║ Ticks:      {:>6}", TICK_COUNT.load(Ordering::SeqCst));
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ SCAN TEST VALUES (for iterative scan tests)                  ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!(
            "║ SCAN_VALUE_A: {:>10}   @ {:p}",
            SCAN_VALUE_A, &SCAN_VALUE_A
        );
        println!(
            "║ SCAN_VALUE_B: {:>10}   @ {:p}",
            SCAN_VALUE_B, &SCAN_VALUE_B
        );
        println!(
            "║ SCAN_VALUE_C: {:>10}   @ {:p}",
            SCAN_VALUE_C, &SCAN_VALUE_C
        );
        println!("║ SCAN_FLOAT:   {:>10.5}   @ {:p}", SCAN_FLOAT, &SCAN_FLOAT);
        println!(
            "║ SCAN_DOUBLE:  {:>10.5}   @ {:p}",
            SCAN_DOUBLE, &SCAN_DOUBLE
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ POINTER CHAIN (for pointer scan tests)                       ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!(
            "║ GAME_STATE_PTR:        {:p} (static base)",
            &GAME_STATE_PTR
        );
        if !GAME_STATE_PTR.is_null() {
            let game = &*GAME_STATE_PTR;
            println!("║   -> GameState:        {:p}", GAME_STATE_PTR);
            println!(
                "║      .enemy_count = {}, .difficulty = {}",
                game.enemy_count, game.difficulty
            );
            if !game.player.is_null() {
                let player = &*game.player;
                println!("║   -> PlayerData:       {:p} (offset +0x00)", game.player);
                println!(
                    "║      .gold = {}, .level = {}, .exp = {}",
                    player.gold, player.level, player.experience
                );
                if !player.stats.is_null() {
                    let stats = &*player.stats;
                    println!("║   -> PlayerStats:      {:p} (offset +0x00)", player.stats);
                    println!(
                        "║      .health = {}/{}, .mana = {}/{}",
                        stats.health, stats.max_health, stats.mana, stats.max_mana
                    );
                    println!(
                        "║      .defence = {}, .attack = {}, .speed = {}",
                        stats.defence, stats.attack, stats.speed
                    );
                }
            }
        } else {
            println!("║   (Not initialized - run 'init' command)");
        }
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ PATTERNS (for AOB scan tests)                                ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ UNIQUE_PATTERN: {:p}", &UNIQUE_PATTERN);
        println!("║   Pattern: DE AD BE EF CA FE BA BE 13 37 42 42 FF 00 AA 55");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }
}

fn print_help() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      AVAILABLE COMMANDS                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ GENERAL:                                                     ║");
    println!("║   status (s)     - Show all values and memory addresses      ║");
    println!("║   init           - Initialize pointer chain structures       ║");
    println!("║   reset (r)      - Reset all values to initial state         ║");
    println!("║   help (h)       - Show this help                            ║");
    println!("║   quit (q)       - Exit the program                          ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ STATIC VALUE CHANGES (for basic scan testing):               ║");
    println!("║   damage N       - Take N damage (decreases HEALTH)          ║");
    println!("║   heal N         - Heal N health                             ║");
    println!("║   gold N         - Add N gold                                ║");
    println!("║   spend N        - Spend N gold                              ║");
    println!("║   xp N           - Add N experience (may level up)           ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ SCAN TEST VALUES (for iterative scan practice):              ║");
    println!("║   seta N         - Set SCAN_VALUE_A to N                     ║");
    println!("║   setb N         - Set SCAN_VALUE_B to N                     ║");
    println!("║   setc N         - Set SCAN_VALUE_C to N                     ║");
    println!("║   setall N       - Set all SCAN_VALUE_* to N                 ║");
    println!("║   inca N         - Increment SCAN_VALUE_A by N               ║");
    println!("║   incb N         - Increment SCAN_VALUE_B by N               ║");
    println!("║   incc N         - Increment SCAN_VALUE_C by N               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ POINTER CHAIN VALUES (for pointer scan testing):             ║");
    println!("║   phealth N      - Set pointer chain health to N             ║");
    println!("║   pdefence N     - Set pointer chain defence to N            ║");
    println!("║   pattack N      - Set pointer chain attack to N             ║");
    println!("║   pgold N        - Set pointer chain gold to N               ║");
    println!("║   pstatus        - Show pointer chain addresses in detail    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

fn reset_state() {
    unsafe {
        // Reset static values
        HEALTH = 100;
        MAX_HEALTH = 100;
        GOLD = 500;
        LEVEL = 1;
        EXPERIENCE = 0;
        TICK_COUNT.store(0, Ordering::SeqCst);

        // Reset scan test values
        SCAN_VALUE_A = 12345;
        SCAN_VALUE_B = 12345;
        SCAN_VALUE_C = 12345;
        SCAN_FLOAT = 3.14160;
        SCAN_DOUBLE = 2.71830000000;

        // Reset pointer chain values if initialized
        if let Some(stats) = get_player_stats() {
            stats.health = 100;
            stats.max_health = 100;
            stats.mana = 50;
            stats.max_mana = 50;
            stats.stamina = 100;
            stats.defence = 25;
            stats.attack = 30;
            stats.speed = 15;
        }
        if let Some(player) = get_player_data() {
            player.gold = 1000;
            player.level = 5;
            player.experience = 75;
        }

        println!("[Game] All state reset!");
    }
}

fn print_pointer_addresses() {
    unsafe {
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║              POINTER CHAIN ADDRESS DETAILS                   ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ Use these for pointer scanning exercises:                    ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ Static Base: GAME_STATE_PTR @ {:p}", &GAME_STATE_PTR);

        if !GAME_STATE_PTR.is_null() {
            let game = &*GAME_STATE_PTR;
            let game_addr = GAME_STATE_PTR as usize;
            println!("║");
            println!("║ Level 0: GameState @ 0x{:X}", game_addr);
            println!("║   +0x00: player (ptr)     = 0x{:X}", game.player as usize);
            println!("║   +0x08: enemy_count (i32) = {}", game.enemy_count);
            println!("║   +0x0C: is_paused (bool)  = {}", game.is_paused);
            println!("║   +0x10: difficulty (i32)  = {}", game.difficulty);

            if !game.player.is_null() {
                let player = &*game.player;
                let player_addr = game.player as usize;
                println!("║");
                println!("║ Level 1: PlayerData @ 0x{:X}", player_addr);
                println!(
                    "║   +0x00: stats (ptr)       = 0x{:X}",
                    player.stats as usize
                );
                println!("║   +0x08: gold (i32)        = {}", player.gold);
                println!("║   +0x0C: level (i32)       = {}", player.level);
                println!("║   +0x10: experience (i32)  = {}", player.experience);

                if !player.stats.is_null() {
                    let stats = &*player.stats;
                    let stats_addr = player.stats as usize;
                    println!("║");
                    println!("║ Level 2: PlayerStats @ 0x{:X}", stats_addr);
                    println!("║   +0x00: health (i32)      = {}", stats.health);
                    println!("║   +0x04: max_health (i32)  = {}", stats.max_health);
                    println!("║   +0x08: mana (i32)        = {}", stats.mana);
                    println!("║   +0x0C: max_mana (i32)    = {}", stats.max_mana);
                    println!("║   +0x10: stamina (i32)     = {}", stats.stamina);
                    println!("║   +0x14: defence (i32)     = {}", stats.defence);
                    println!("║   +0x18: attack (i32)      = {}", stats.attack);
                    println!("║   +0x1C: speed (i32)       = {}", stats.speed);
                    println!("║");
                    println!("║ POINTER PATH TO DEFENCE:");
                    println!("║   [GAME_STATE_PTR] -> +0x00 -> +0x00 -> +0x14");
                    println!("║   Base: 0x{:X}", &GAME_STATE_PTR as *const _ as usize);
                    println!(
                        "║   Target: 0x{:X} (defence value: {})",
                        stats_addr + 0x14,
                        stats.defence
                    );
                }
            }
        } else {
            println!("║ (Not initialized - run 'init' command first)");
        }
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!(
        "║     Ghost-MCP Interactive Test Target v{}              ║",
        env!("CARGO_PKG_VERSION")
    );
    println!("║     For testing memory scan, read, write, patch & pointers   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Initialize pointer chain on startup
    init_pointer_chain();

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
            // General commands
            "status" | "s" => print_status(),
            "help" | "h" | "?" => print_help(),
            "quit" | "exit" | "q" => break,
            "reset" | "r" => reset_state(),
            "init" => {
                init_pointer_chain();
                println!("[Game] Pointer chain re-initialized!");
            }

            // Static value commands
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

            // Scan test value commands
            "seta" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_A = val;
                    }
                    println!("[Scan] SCAN_VALUE_A = {}", val);
                } else {
                    println!("Usage: seta <value>");
                }
            }
            "setb" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_B = val;
                    }
                    println!("[Scan] SCAN_VALUE_B = {}", val);
                } else {
                    println!("Usage: setb <value>");
                }
            }
            "setc" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_C = val;
                    }
                    println!("[Scan] SCAN_VALUE_C = {}", val);
                } else {
                    println!("Usage: setc <value>");
                }
            }
            "setall" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_A = val;
                        SCAN_VALUE_B = val;
                        SCAN_VALUE_C = val;
                    }
                    println!("[Scan] All SCAN_VALUE_* = {}", val);
                } else {
                    println!("Usage: setall <value>");
                }
            }
            "inca" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_A += val;
                    }
                    println!("[Scan] SCAN_VALUE_A += {} (now {})", val, unsafe {
                        SCAN_VALUE_A
                    });
                } else {
                    println!("Usage: inca <amount>");
                }
            }
            "incb" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_B += val;
                    }
                    println!("[Scan] SCAN_VALUE_B += {} (now {})", val, unsafe {
                        SCAN_VALUE_B
                    });
                } else {
                    println!("Usage: incb <amount>");
                }
            }
            "incc" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    unsafe {
                        SCAN_VALUE_C += val;
                    }
                    println!("[Scan] SCAN_VALUE_C += {} (now {})", val, unsafe {
                        SCAN_VALUE_C
                    });
                } else {
                    println!("Usage: incc <amount>");
                }
            }

            // Pointer chain commands
            "pstatus" => print_pointer_addresses(),
            "phealth" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    if let Some(stats) = get_player_stats() {
                        stats.health = val;
                        println!("[Pointer] PlayerStats.health = {}", val);
                    } else {
                        println!("[Error] Pointer chain not initialized. Run 'init' first.");
                    }
                } else {
                    println!("Usage: phealth <value>");
                }
            }
            "pdefence" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    if let Some(stats) = get_player_stats() {
                        stats.defence = val;
                        println!("[Pointer] PlayerStats.defence = {}", val);
                    } else {
                        println!("[Error] Pointer chain not initialized. Run 'init' first.");
                    }
                } else {
                    println!("Usage: pdefence <value>");
                }
            }
            "pattack" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    if let Some(stats) = get_player_stats() {
                        stats.attack = val;
                        println!("[Pointer] PlayerStats.attack = {}", val);
                    } else {
                        println!("[Error] Pointer chain not initialized. Run 'init' first.");
                    }
                } else {
                    println!("Usage: pattack <value>");
                }
            }
            "pgold" => {
                if let Some(val) = parts.get(1).and_then(|s| s.parse::<i32>().ok()) {
                    if let Some(player) = get_player_data() {
                        player.gold = val;
                        println!("[Pointer] PlayerData.gold = {}", val);
                    } else {
                        println!("[Error] Pointer chain not initialized. Run 'init' first.");
                    }
                } else {
                    println!("Usage: pgold <value>");
                }
            }

            _ => println!("Unknown command. Type 'help' for available commands."),
        }
    }

    println!("Goodbye!");
}
