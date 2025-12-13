use num_traits::int::PrimInt;

/// Trait that both LFSR and NFSR will implement.
///
/// This trait provide a method to apply a feedback function
/// to the xFSR state and a clock method to clock once the xFSR
pub(crate) trait Xfsr<T: PrimInt> {
    fn get_state(&self) -> u128;

    fn set_state(&mut self, new_value: u128);

    fn feedback_function(&self) -> u128;

    fn clock(&mut self) -> T {
        let size = (T::max_value()).count_ones() as usize;
        let mask = (1 << size) - 1;

        let state = self.get_state();

        let output = T::from(state & mask).expect("Unable to clock xFSR");

        self.set_state((state >> size) | (self.feedback_function() << (128 - size)));

        output
    }
}

pub(crate) trait Accumulator<T> {
    fn accumulate(&mut self, new: T) -> T;
    fn new() -> Self;
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ops::{BitAnd, Shr};
    use num_traits::cast::{FromPrimitive, ToPrimitive};
    use num_traits::identities::One;
    use num_traits::sign::Unsigned;

    // Useful function for clocking the
    // LFSR/NFSR during the tests
    /// Extract the next 8 bits starting from a given position.
    fn get_byte_at_bit<T: Unsigned + BitAnd<Output = T> + One + ToPrimitive + FromPrimitive>(
        value: &T,
        index: usize,
    ) -> u8
    where
        for<'a> &'a T: Shr<usize, Output = T>,
    {
        ((value >> index) & T::from_u8(0xff).expect("Unable to get the given byte"))
            .to_u8()
            .expect("Unable extract the given byte index")
    }

    struct Lfsr {
        pub(crate) state: u128,
    }

    struct Nfsr {
        pub(crate) state: u128,
    }

    impl Xfsr<u8> for Lfsr {
        fn get_state(&self) -> u128 {
            self.state
        }

        fn set_state(&mut self, new_value: u128) {
            self.state = new_value
        }
        #[inline(always)]
        fn feedback_function(&self) -> u128 {
            (get_byte_at_bit(&self.state, 0)
                ^ get_byte_at_bit(&self.state, 4)
                ^ get_byte_at_bit(&self.state, 7)
                ^ get_byte_at_bit(&self.state, 33)) as u128
        }
    }

    impl Xfsr<u8> for Nfsr {
        fn get_state(&self) -> u128 {
            self.state
        }

        fn set_state(&mut self, new_value: u128) {
            self.state = new_value
        }

        #[inline(always)]
        fn feedback_function(&self) -> u128 {
            ((get_byte_at_bit(&self.state, 0) & get_byte_at_bit(&self.state, 4))
                ^ (get_byte_at_bit(&self.state, 7) & get_byte_at_bit(&self.state, 33)))
                as u128
        }
    }

    #[test]
    fn test_lfsr() {
        let mut lfsr = Lfsr {
            state: 827238322173621362173923281382u128,
        };

        let output: u8 = lfsr.clock();

        assert_eq!(output, 230);
        assert_eq!(lfsr.state, 45193751859918539374720148495523603401);
    }

    #[test]
    fn test_nfsr() {
        let mut nfsr = Nfsr {
            state: 827238322173621362173923281382u128,
        };

        let output: u8 = nfsr.clock();

        assert_eq!(output, 230);
        assert_eq!(nfsr.state, 9304595973725810806317357867954299849);
    }
}
