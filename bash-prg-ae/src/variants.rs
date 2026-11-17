//! Type aliases for bash-prg-ae variants

use super::BashPrgAe;
use aead::consts::{U16, U24, U32};

/// `bash-prg-ae` with ℓ = 128, d = 1 and a 16-octet nonce
pub type BashPrgAe1281 = BashPrgAe<U16, 1, U16>;

/// `bash-prg-ae` with ℓ = 128, d = 2 and a 16-octet nonce
pub type BashPrgAe1282 = BashPrgAe<U16, 2, U16>;

/// `bash-prg-ae` with ℓ = 192, d = 1 and a 16-octet nonce
pub type BashPrgAe1921 = BashPrgAe<U24, 1, U16>;

/// `bash-prg-ae` with ℓ = 192, d = 2 and a 16-octet nonce
pub type BashPrgAe1922 = BashPrgAe<U24, 2, U16>;

/// `bash-prg-ae` with ℓ = 256, d = 1 and a 16-octet nonce
pub type BashPrgAe2561 = BashPrgAe<U32, 1, U16>;

/// `bash-prg-ae` with ℓ = 256, d = 2 and a 16-octet nonce
pub type BashPrgAe2562 = BashPrgAe<U32, 2, U16>;
