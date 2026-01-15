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

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::{certified_data_set, data_certificate, msg_caller, time};
use ic_cdk::management_canister::raw_rand;
use ic_cdk::{export_candid, init, post_upgrade, pre_upgrade, query, update};
use ic_http_certification::{
    utils::add_v2_certificate_header, DefaultCelBuilder, DefaultResponseCertification,
    DefaultResponseOnlyCelExpression, HeaderField, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest, HttpResponse, StatusCode,
    CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{
    DefaultMemoryImpl, RestrictedMemory, StableBTreeMap, StableCell,
    Storable,
};
use lazy_static::lazy_static;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;

type Memory = VirtualMemory<DefaultMemoryImpl>;

const MAX_INGRESS_SIZE: usize = 2_000_000; // ~2MB

lazy_static! {
    static ref CEL_EXPR: DefaultResponseOnlyCelExpression<'static> = DefaultCelBuilder::response_only_certification()
    .with_response_certification(DefaultResponseCertification::response_header_exclusions(
        vec![],
    ))
    .build();
}

#[derive(CandidType, Deserialize, Clone)]
pub struct AssetMetadata {
    pub uuid: String,
    pub content_type: String,
    pub total_size: u64,
    pub created_at: u64,
    pub owner: Principal,
    pub chunks_count: u32,
    pub is_complete: bool,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct AssetChunk {
    pub chunk_index: u32,
    pub data: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct UploadChunkArgs {
    pub path: String,
    pub chunk_index: u32,
    pub data: Vec<u8>,
    pub is_last_chunk: bool,
}

#[derive(CandidType, Deserialize)]
pub struct InitAssetUploadArgs {
    pub content_type: String,
    pub total_size: u64,
    pub chunks_count: u32,
}

#[derive(CandidType, Deserialize)]
pub struct InitAssetUploadResult {
    pub uuid: String,
    pub url: String,
}

#[derive(CandidType, Deserialize)]
pub struct PrincipalUsage {
    pub total_bytes: u64,
    pub asset_count: u32,
}

impl Storable for AssetMetadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
    
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
}

impl Storable for AssetChunk {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
    
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
}

impl Storable for PrincipalUsage {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
    
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // Stable storage for assets metadata
    static ASSETS: RefCell<StableBTreeMap<String, AssetMetadata, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    // Stable storage for asset chunks
    static ASSET_CHUNKS: RefCell<StableBTreeMap<String, AssetChunk, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );

    // Authorized principals
    static AUTHORIZED_PRINCIPALS: RefCell<StableBTreeMap<Principal, (), Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        )
    );

    // Principal usage tracking
    static PRINCIPAL_USAGE: RefCell<StableBTreeMap<Principal, PrincipalUsage, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
        )
    );

    // Controller principal
    static CONTROLLER: RefCell<StableCell<Principal, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
            Principal::anonymous()
        )
    );

    // Modern HTTP certification
    static HTTP_TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());
    static ASSET_CERT: RefCell<HashMap<String, HttpCertification>> = RefCell::new(HashMap::new());
}

fn is_controller() -> bool {
    if ic_cdk::api::is_controller(&msg_caller()) {
        return true;
    }
    CONTROLLER.with_borrow(|controller| controller.get() == &msg_caller())
}

fn is_authorized() -> bool {
    let caller_principal = msg_caller();
    
    // Controller is always authorized
    if is_controller() {
        return true;
    }
    
    AUTHORIZED_PRINCIPALS.with(|principals| {
        principals.borrow().contains_key(&caller_principal)
    })
}


fn build_asset_path(uuid: &str) -> String {
    format!("/assets/{}", uuid)
}


fn create_chunk_key(uuid: &str, chunk_index: u32) -> String {
    format!("{}_{}", uuid, chunk_index)
}

fn get_asset_headers(
    content_type: String,
    content_length: usize,
    cel_expr: String,
) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), content_type),
        ("content-length".to_string(), content_length.to_string()),
        (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr),
    ]
}

fn update_asset_certification(path: String, content: &[u8], content_type: &str) {
    
    let headers = get_asset_headers(
        content_type.to_string(),
        content.len(),
        CEL_EXPR.to_string(),
    );

    let response = HttpResponse::builder()
        .with_body(content.to_vec())
        .with_status_code(StatusCode::OK)
        .with_headers(headers)
        .build();

    let certification = HttpCertification::response_only(&CEL_EXPR, &response, None).unwrap();
    let cert_path = HttpCertificationPath::exact(path.clone());

    HTTP_TREE.with_borrow_mut(|http_tree| {
        http_tree.insert(&HttpCertificationTreeEntry::new(
            cert_path,
            &certification,
        ));
    });

    ASSET_CERT.with_borrow_mut(|cert_map| {
        cert_map.insert(path, certification);
    });

    update_certified_data();
}

fn update_certified_data() {
    HTTP_TREE.with_borrow(|http_tree| {
        certified_data_set(&http_tree.root_hash());
    });
}

fn create_certified_error_response(
    status_code: StatusCode,
    content_type: String,
    body: &'static [u8],
    path: String,
) {
    let headers = get_asset_headers(
        content_type,
        body.len(),
        CEL_EXPR.to_string(),
    );

    let mut response = HttpResponse::builder()
        .with_status_code(status_code)
        .with_headers(headers.clone())
        .with_body(body.to_vec())
        .build();

    // Certify the error response
    let certification = HttpCertification::response_only(&CEL_EXPR, &response, None).unwrap();
    let cert_path = HttpCertificationPath::exact(&path);

    HTTP_TREE.with_borrow_mut(|http_tree| {
        http_tree.insert(&HttpCertificationTreeEntry::new(
            cert_path.clone(),
            &certification,
        ));
    });

    ASSET_CERT.with_borrow_mut(|cert_map| {
        cert_map.insert(path.clone(), certification);
    });

    update_certified_data();
}

fn get_error_response(status_code: StatusCode, content_type: String, body: &'static [u8], path: String) -> HttpResponse<'static> {
    ASSET_CERT.with_borrow(|cert_map| {
        let headers = get_asset_headers(
            content_type.clone(),
            body.len(),
            CEL_EXPR.to_string(),
        );

        let mut response = HttpResponse::builder()
            .with_status_code(status_code)
            .with_headers(headers)
            .with_body(body.to_vec())
            .build();

        if let Some(cert) = cert_map.get(&path) {
            HTTP_TREE.with_borrow(|http_tree| {
                let asset_tree_path = HttpCertificationPath::exact(&path);

                add_v2_certificate_header(
                    &data_certificate().expect("No data certificate available"),
                    &mut response,
                    &http_tree
                        .witness(
                            &HttpCertificationTreeEntry::new(&asset_tree_path, cert),
                            &path,
                        )
                        .unwrap(),
                    &asset_tree_path.to_expr_path(),
                );
            })
        } else {
            ic_cdk::trap("No certification found");
        };

        response
    })

}

#[init]
fn init() {
    CONTROLLER.with(|controller| {
        controller.borrow_mut().set(msg_caller());
    });
}

#[post_upgrade]
fn post_upgrade() {
    // Rebuild certification tree
    ASSETS.with_borrow(|assets| {
        for entry in assets.iter() {
            let metadata = entry.value();
            let path = entry.key();
            if metadata.is_complete {
                // Reconstruct the full asset content for certification
                let mut full_content = Vec::new();
                
                ASSET_CHUNKS.with(|chunks| {
                    for chunk_index in 0..metadata.chunks_count {
                        let chunk_key = create_chunk_key(&metadata.uuid, chunk_index);
                        if let Some(chunk) = chunks.borrow().get(&chunk_key) {
                            full_content.extend_from_slice(&chunk.data);
                        }
                    }
                });
                
                update_asset_certification(path.clone(), &full_content, &metadata.content_type);
            }
        }
    });

    create_certified_error_response(
        StatusCode::NOT_FOUND,
        "text/html".to_string(),
        b"Not Found",
        "/404".to_string(),
    );

    create_certified_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "text/html".to_string(),
        b"Internal Server Error",
        "/500".to_string(),
    );



}

#[update]
fn authorize(principal: Principal) -> Result<(), String> {
    if !is_controller() {
        return Err("Only controller can authorize principals".to_string());
    }
    
    AUTHORIZED_PRINCIPALS.with(|principals| {
        principals.borrow_mut().insert(principal, ());
    });
    
    Ok(())
}

#[update]
fn deauthorize(principal: Principal) -> Result<(), String> {
    if !is_controller() {
        return Err("Only controller can deauthorize principals".to_string());
    }
    
    AUTHORIZED_PRINCIPALS.with(|principals| {
        principals.borrow_mut().remove(&principal);
    });
    
    Ok(())
}

#[query]
fn is_principal_authorized(principal: Principal) -> bool {
    if CONTROLLER.with(|controller| controller.borrow().get() == &principal) {
        return true;
    }
    
    AUTHORIZED_PRINCIPALS.with(|principals| {
        principals.borrow().contains_key(&principal)
    })
}

#[query]
fn get_principal_usage(principal: Option<Principal>) -> Option<PrincipalUsage> {
    let usage = match principal {
        Some(p) => {
            if is_controller() {
                return None;
            }
            PRINCIPAL_USAGE.with(|usage| {
                usage.borrow().get(&p)
            })
        },
        None => {
            PRINCIPAL_USAGE.with(|usage| {
                usage.borrow().get(&msg_caller())
            })
        },
    };
    
    usage
}

#[update]
async fn init_asset_upload(args: InitAssetUploadArgs) -> Result<InitAssetUploadResult, String> {
    if !is_authorized() {
        return Err("Not authorized to upload assets".to_string());
    }
    
    let uuid = hex::encode(raw_rand().await.unwrap());
    let caller_principal = msg_caller();
    let current_time = time();
    
    let metadata = AssetMetadata {
        uuid: uuid.clone(),
        content_type: args.content_type,
        total_size: args.total_size,
        created_at: current_time,
        owner: caller_principal,
        chunks_count: args.chunks_count,
        is_complete: false,
    };

    let url = build_asset_path(&uuid);
    
    ASSETS.with(|assets| {
        assets.borrow_mut().insert(url.clone(), metadata);
    });
    
   
    
    Ok(InitAssetUploadResult { uuid, url })
}

#[update]
fn upload_chunk(args: UploadChunkArgs) -> Result<(), String> {
    if !is_authorized() {
        return Err("Not authorized to upload assets".to_string());
    }
    
    let caller_principal = msg_caller();
    
    // Verify asset exists and belongs to caller
    let metadata = ASSETS.with(|assets| {
        assets.borrow().get(&args.path)
    }).ok_or("Asset not found")?;
    
    if metadata.owner != caller_principal {
        return Err("Not the owner of this asset".to_string());
    }
    
    if metadata.is_complete {
        return Err("Asset upload already completed".to_string());
    }
    
    if args.chunk_index >= metadata.chunks_count {
        return Err("Invalid chunk index".to_string());
    }
    
    let chunk_key = create_chunk_key(&metadata.uuid, args.chunk_index);
    let chunk = AssetChunk {
        chunk_index: args.chunk_index,
        data: args.data.clone(),
    };
    
    ASSET_CHUNKS.with(|chunks| {
        chunks.borrow_mut().insert(chunk_key, chunk);
    });
    
    // Check if all chunks are uploaded
    if args.is_last_chunk {
        let mut all_chunks_present = true;
        
        ASSET_CHUNKS.with(|chunks| {
            for chunk_index in 0..metadata.chunks_count {
                let chunk_key = create_chunk_key(&metadata.uuid, chunk_index);
                if !chunks.borrow().contains_key(&chunk_key) {
                    all_chunks_present = false;
                    break;
                }
            }
        });
        
        if all_chunks_present {
            // Mark asset as complete
            let mut updated_metadata = metadata.clone();
            updated_metadata.is_complete = true;
            
            ASSETS.with(|assets| {
                assets.borrow_mut().insert(args.path.clone(), updated_metadata.clone());
            });
            
            // Update principal usage
            PRINCIPAL_USAGE.with(|usage| {
                let mut usage_map = usage.borrow_mut();
                let current_usage = usage_map.get(&caller_principal).unwrap_or(PrincipalUsage {
                    total_bytes: 0,
                    asset_count: 0,
                });
                
                let new_usage = PrincipalUsage {
                    total_bytes: current_usage.total_bytes + updated_metadata.total_size,
                    asset_count: current_usage.asset_count + 1,
                };
                
                usage_map.insert(caller_principal, new_usage);
            });
            
            // Reconstruct full content and update certification
            let mut full_content = Vec::new();
            ASSET_CHUNKS.with(|chunks| {
                for chunk_index in 0..metadata.chunks_count {
                    let chunk_key = create_chunk_key(&metadata.uuid, chunk_index);
                    if let Some(chunk) = chunks.borrow().get(&chunk_key) {
                        full_content.extend_from_slice(&chunk.data);
                    }
                }
            });
            
            update_asset_certification(args.path, &full_content, &metadata.content_type);
        }
    }
    
    Ok(())
}

#[query]
fn get_asset_metadata(uuid: String) -> Option<AssetMetadata> {
    ASSETS.with(|assets| {
        assets.borrow().get(&uuid)
    })
}

#[query]
fn http_request(request: HttpRequest) -> HttpResponse {
    let path = request.get_path().expect("No path found");

    ic_cdk::println!("Serving asset: {}", path);

    let response = serve_asset(path);

    ic_cdk::println!("Response: {:?}", response);

    response
}

fn serve_asset(path: String) -> HttpResponse<'static> {
    let metadata = match ASSETS.with(|assets| assets.borrow().get(&path)) {
        Some(metadata) => metadata,
        None => {
            return get_error_response(StatusCode::NOT_FOUND, "text/html".to_string(), b"Not Found", "/404".to_string());
        }
    };
    
    if !metadata.is_complete {
        return get_error_response(StatusCode::SERVICE_UNAVAILABLE, "text/html".to_string(), b"Service Unavailable", "/503".to_string());
    }
    
    // Reconstruct the full asset from chunks
    let mut full_content = Vec::new();
    ASSET_CHUNKS.with(|chunks| {
        for chunk_index in 0..metadata.chunks_count {
            let chunk_key = create_chunk_key(&metadata.uuid, chunk_index);
            if let Some(chunk) = chunks.borrow().get(&chunk_key) {
                full_content.extend_from_slice(&chunk.data);
            }
        }
    });
    
    ASSET_CERT.with_borrow(|cert_map| {
        let headers = get_asset_headers(
            metadata.content_type.clone(),
            full_content.len(),
            CEL_EXPR.to_string(),
        );

        let mut response = HttpResponse::builder()
            .with_status_code(StatusCode::OK)
            .with_headers(headers)
            .with_body(full_content)
            .build();

        if let Some(cert) = cert_map.get(&path) {
            HTTP_TREE.with_borrow(|http_tree| {
                let asset_tree_path = HttpCertificationPath::exact(&path);

                add_v2_certificate_header(
                    &data_certificate().expect("No data certificate available"),
                    &mut response,
                    &http_tree
                        .witness(
                            &HttpCertificationTreeEntry::new(&asset_tree_path, cert),
                            &path,
                        )
                        .unwrap(),
                    &asset_tree_path.to_expr_path(),
                );
            })
        };

        response
    })
}

export_candid!();