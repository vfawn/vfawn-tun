// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Workspace chores that do not belong in the product crates.

mod loc;
mod refer;

fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();
    match command.as_str() {
        "loc" => loc::run(),
        "refer-check" => refer::run(),
        other => {
            eprintln!("unknown command {other:?}; expected `loc` or `refer-check`");
            std::process::exit(2);
        }
    }
}
