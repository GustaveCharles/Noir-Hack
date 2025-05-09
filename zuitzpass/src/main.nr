use jwt::JWT;
use std::{hash::{poseidon2::Poseidon2::hash, }, hash};
use trees::{merkle::{Calculator, MerkleTree}};



// I know a valid RS256 JWT whose email claim is in the approved merkle-set.
/*
What's going on

JWT verification
You pass in the Base64 encoded header and payload (data), your RSA public key limbs, Redc params and signature limbs.
The library decodes the payload, hashes with SHA256 under the hood (or does a partial-hash variant), and checks the RSA signature.

jwt.get_claim_string("email")
Pulls the "email" claim bytes out of the JSON payload.
You can choose to only extract it, or additionally assert_claim_string(...) if you want it as a public input.

Merkle proof
We turn the email bytes into a field-based leaf hash.
Then we run your merkle-proof code over proof_nodes (the sibling hashes) and proof_path_bits (the left/right path indicators).
Finally you assert that the computed root equals the public merkle_root.
*/

global MAX_EMAIL_LENGTH:   u32 = 64; 
global MAX_DATA_LENGTH: u32 = 512; // max length of signed data (headerb64 + "." + payloadb64)
global MAX_NONCE_LENGTH: u32 = 32; // we are verifying `nonce` claim
global M: u32 = 2;

// how many Field-limbs we'll chunk the email into before hashing:
global LEAF_LIMBS:  u32 = 8;

// Merkle parameters:
global TREE_DEPTH:  u32 = 8;   // e.g. a 2^8-leaf tree //256 participants max at Zuitzerland

fn main(
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    base64_decode_offset: u32,
    pubkey_modulus_limbs: pub [u128; 18],
    redc_params_limbs: [u128; 18],
    signature_limbs: [u128; 18],
    merkle_root:           pub Field,
    proof_siblings:        [Field; TREE_DEPTH],  // sibling hashes
    proof_index:           Field,                // leaf index in the tree
) {
    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    // Verify `iss` claim value is "test"
    //TODO: Is the below line needed?
    //jwt.assert_claim_string("iss".as_bytes(), BoundedVec::<u8, 4>::from_array("test".as_bytes()));

    let email: BoundedVec<u8, MAX_EMAIL_LENGTH> = jwt.get_claim_string("email".as_bytes());
    let email_fields: [Field; M] = boundedvec_to_fields(email);
    // 2) Poseidon-hash those limbs down to one Field
    let leaf: Field = hash(email_fields, LEAF_LIMBS);
    // 3) Verify the Merkle proof
    belongs_to_merkle_tree(merkle_root, poseidon_hasher, leaf, proof_index, proof_siblings)
}

//-----------------------------------------------------------------------------
// 1) Your byte to field conversion (truncates the 32nd byte)
// from here: https://github.com/noir-lang/noir/blob/5d782f020f6aec6aaa8a445c3a6a5fb9b275e3c6/test_programs/execution_success/ram_blowup_regression/src/main.nr
//-----------------------------------------------------------------------------
pub fn field_from_bytes_32_trunc(bytes32: [u8; 32]) -> Field {
    let mut v: Field     = 1;
    let mut high: Field  = 0 as Field;
    let mut low:  Field  = 0 as Field;

    // pack bytes16..30 into `low`, bytes0..14 into `high`, ignore byte31
    for i in 0..15 {
        low  = low  + (bytes32[15 + 15 - i] as Field) * v;
        v    = v    * 256;
        high = high + (bytes32[14 - i] as Field) * v;
    }
    // byte15
    low = low + (bytes32[15] as Field) * v;

    low + high * v
}

//-----------------------------------------------------------------------------
// 2) Chop a BoundedVec<u8,N> into M chunks of 32-bytes and convert each
//-----------------------------------------------------------------------------
fn boundedvec_to_fields(vec: BoundedVec<u8, MAX_EMAIL_LENGTH>) -> [Field; M] {
    let mut fields: [Field; M] = [0; M];
    for i in 0..M {
        // build a 32-byte window
        let mut chunk: [u8; 32] = [0; 32];
        for j in 0..32 {
            let idx = i * 32 + j;
            if idx < vec.len() {
                chunk[j] = vec.storage()[idx];
            }
        }
        fields[i] = field_from_bytes_32_trunc(chunk);
    }
    fields
}

fn belongs_to_merkle_tree(root: Field, hasher : fn([Field; 2]) -> Field, leaf : Field, indexes : Field, hash_path: [Field; TREE_DEPTH]) {
    let mut mt = MerkleTree::from(root, hasher);
    mt.membership(leaf, indexes, hash_path);
}

// Create a hasher function that can be used with MerkleTree
pub fn poseidon_hasher(inputs: [Field; 2]) -> Field {
    hash(inputs,2)
}

#[test]
fn test_merkle_membership() {   

    // Create test data for a simple Merkle tree
    let leaf = 42;
    let indexes = 0; // Position in the tree
    // 2) build a dummy sibling path
    let hash_path: [Field; TREE_DEPTH] = [123; TREE_DEPTH];
    // 3) build tree and get the real root
    let root: Field = MerkleTree::new(poseidon_hasher).calculate_root(leaf, indexes, hash_path);
    let mut mt1 = MerkleTree::from(root,poseidon_hasher);
    
    // Test the membership function
    belongs_to_merkle_tree(root, poseidon_hasher, leaf, indexes, hash_path);
}

#[test(should_fail)]
fn test_merkle_membership_wrong_leaf() {
    // Create test data for a simple Merkle tree
    let leaf = 42;
    let indexes = 0; // Position in the tree
    let hash_path = [123, 234, 345, 456, 567, 678, 789, 890];
    
    // Calculate what the root should be by manually applying the hash function
    // This simulates what would happen inside the MerkleTree::membership function
    let node1 = poseidon_hasher([leaf, hash_path[0]]);
    let root = poseidon_hasher([node1, hash_path[1]]);

    // Negative test case
    let wrong_leaf = 43;
    belongs_to_merkle_tree(root, poseidon_hasher, wrong_leaf, indexes, hash_path);
}

#[test]
fn test_main() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;


    // Create test data for a simple Merkle tree
    let expected_email: BoundedVec<u8, 64> = BoundedVec::from_array("alice@test.com".as_bytes());
    let email_fields: [Field; M] = boundedvec_to_fields(expected_email);
    let leaf: Field = hash(email_fields, LEAF_LIMBS);
    let indexes = 0; // Position in the tree
    // 2) build a dummy sibling path
    let hash_path: [Field; TREE_DEPTH] = [123; TREE_DEPTH];
    // 3) build tree and get the real root
    let root: Field = MerkleTree::new(poseidon_hasher).calculate_root(leaf, indexes, hash_path);
    let mut mt1 = MerkleTree::from(root,poseidon_hasher);
    main(data, base64_decode_offset, pubkey_modulus_limbs, redc_params_limbs, signature_limbs, root, hash_path, indexes)

}

#[test]
fn test_get_claim_string() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt: JWT<512> = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let email: BoundedVec<u8, 64> = jwt.get_claim_string("email".as_bytes());
    let expected_email: BoundedVec<u8, 64> = BoundedVec::from_array("alice@test.com".as_bytes());
    assert(email == expected_email);
}
