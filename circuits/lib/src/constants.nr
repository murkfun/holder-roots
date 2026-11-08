// GENERATED (EIP-712 constants of MurkFun orders, holder tree empty roots). Do not edit.

pub global BATCH_LOG: u32 = 10;
pub global GLOBAL_LOG: u32 = 16;
pub global DEPTH: u32 = 26;
pub global BATCH_SIZE: u32 = 1024;

/// EIP712Domain(name "MurkFun Order", version "1", chainId 56)
pub global DOMAIN_SEPARATOR: [u8; 32] = [
    0x2f, 0xf4, 0x1b, 0x54, 0xa6, 0x80, 0xd9, 0xd4, 0x21, 0xc6, 0x0c, 0x86, 0x7e, 0x47, 0x0d, 0xf7,
    0xf3, 0xb6, 0x20, 0xfb, 0x2d, 0x72, 0x1a, 0x22, 0x20, 0x6d, 0x9f, 0x2e, 0xc9, 0x5b, 0x79, 0x54,
];
/// keccak256("OrderAuth(bytes32 orderHash)")
pub global ORDER_AUTH_TYPEHASH: [u8; 32] = [
    0xe9, 0x28, 0x6a, 0x31, 0x2c, 0x83, 0x88, 0x6d, 0xa0, 0xbe, 0x48, 0x77, 0x2d, 0x89, 0x86, 0x3a,
    0x08, 0xea, 0x1f, 0xc0, 0x55, 0x5d, 0x85, 0x33, 0x8d, 0x05, 0xd1, 0x9c, 0x17, 0x71, 0xcc, 0xd1,
];
/// EIP-712 digest of MurkFunSeed{purpose} (S1, the same for every wallet)
pub global SEED_DIGEST: [u8; 32] = [
    0x2e, 0x2b, 0x4d, 0x17, 0xf6, 0xd9, 0x43, 0x3a, 0x3c, 0x8a, 0xd6, 0xfb, 0x03, 0x20, 0x49, 0x59,
    0xf4, 0xbd, 0x6d, 0xc1, 0x3a, 0x1f, 0x84, 0x95, 0x9c, 0x1e, 0x2d, 0x56, 0x46, 0x3d, 0xfb, 0x6f,
];

pub global TAG_SECRET: Field = 0x6d75726b2e736563726574;
pub global TAG_PSEUDONYM: Field = 0x6d75726b2e70736575646f6e796d;
pub global TAG_NULLIFIER: Field = 0x6d75726b2e6e756c6c6966696572;
pub global TAG_ORDER: Field = 0x6d75726b2e6f72646572;

/// ZEROS[i] = root of an empty subtree of height i (empty leaf = 0)
pub global ZEROS: [Field; 27] = [
    0x0,
    0xb63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1,
    0xe34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290,
    0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20,
    0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e,
    0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf,
    0x1c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76,
    0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b,
    0x67243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1,
    0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972,
    0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686,
    0xf320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7,
    0xd07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73,
    0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1,
    0x197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a,
    0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9,
    0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3,
    0x71d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3,
    0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5,
    0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5,
    0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755,
    0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3,
    0x38146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30,
    0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4,
    0xe1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491,
    0x9244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2,
    0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9,
];
