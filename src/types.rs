// Copyright 2025 Declan Nnadozie
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use candid::{CandidType, Deserialize};
use ic_http_certification::HeaderField;
use serde::Serialize;
use ic_stable_structures::{Storable, storable::Bound};
use std::borrow::Cow;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Asset {
    pub path: String,
    pub content: Vec<u8>,
    pub additional_headers: Vec<HeaderField>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct AssetResponse {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Storable for AssetResponse {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}