//! Type aliases for bash-prg-ae variants

use super::BashPrgAe;
use aead::consts::*;

/// `bash-prg-ae` with ℓ = 128 and d = 1
pub type BashPrgAe1281<NonceSize = U16> = BashPrgAe<U16, 1, NonceSize>;

/// `bash-prg-ae` with ℓ = 128 and d = 2
pub type BashPrgAe1282<NonceSize = U16> = BashPrgAe<U16, 2, NonceSize>;

/// `bash-prg-ae` with ℓ = 192 and d = 1
pub type BashPrgAe1921<NonceSize = U16> = BashPrgAe<U24, 1, NonceSize>;

/// `bash-prg-ae` with ℓ = 192 and d = 2
pub type BashPrgAe1922<NonceSize = U16> = BashPrgAe<U24, 2, NonceSize>;

/// `bash-prg-ae` with ℓ = 256 and d = 1
pub type BashPrgAe2561<NonceSize = U16> = BashPrgAe<U32, 1, NonceSize>;

/// `bash-prg-ae` with ℓ = 256 and d = 2
pub type BashPrgAe2562<NonceSize = U16> = BashPrgAe<U32, 2, NonceSize>;
