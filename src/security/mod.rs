pub mod timecode;

// Exposeer de tijdscode-functies direct aan de rest van de library
pub use timecode::{generate_timecode, TimeCode};
