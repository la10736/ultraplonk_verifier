// Copyright 2024, The Horizen Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "noir-cli")]
#[command(
    about = "Utility for handling zero-knowledge proof verification keys and proof data in Noir-lang. Converts Solidity verification keys to binary format, processes proof data from JSON files, and verifies proofs against public inputs and verification keys."
)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Convert Solidity verification key to binary format
    Key {
        /// Input file for verification key
        #[arg(long)]
        input: PathBuf,

        /// Output file for verification key [or stdout if not specified]
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Process proof data from JSON file
    ProofData {
        /// Input file for verification key
        #[arg(long)]
        input_json: PathBuf,

        /// Output file for proof data [or stdout if not specified]
        #[arg(long)]
        output_proof: Option<PathBuf>,

        /// Output file for verification key [or stdout if not specified]
        #[arg(long)]
        output_pubs: Option<PathBuf>,
    },
    /// Verify proof with key
    Verify {
        /// Proof file
        #[arg(long)]
        proof: PathBuf,

        /// Input file for verification key
        #[arg(long)]
        pubs: PathBuf,

        /// Key file
        #[arg(long)]
        key: PathBuf,
    },
}