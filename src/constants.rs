// constants.rs - constants for noise based wire protocol
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pub const NOISE_PARAMS: & str = "Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2b";
pub const PROLOGUE: [u8;1] = [1u8;1];
pub const PROLOGUE_SIZE: usize = 1;
pub const NOISE_MESSAGE_MAX_SIZE: usize = 65535;
pub const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const MAX_ADDITIONAL_DATA_SIZE: usize = 255;
pub const AUTH_MESSAGE_SIZE: usize = 1 + 8 + MAX_ADDITIONAL_DATA_SIZE;
pub const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = 1600 + PROLOGUE_SIZE;
pub const NOISE_HANDSHAKE_MESSAGE2_SIZE: usize = 1680 + AUTH_MESSAGE_SIZE;
pub const NOISE_HANDSHAKE_MESSAGE3_SIZE: usize = 328;
pub const NOISE_MESSAGE_HEADER_SIZE: usize = MAC_SIZE + 4;
