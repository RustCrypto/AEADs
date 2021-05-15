const ROOT: u8 = 0x1b;

fn mul_by_2(value: u8) -> u8 {
    let multiplied_val = value << 1;
    if (value >> 7) == 1 {
        multiplied_val ^ ROOT
    } else {
        multiplied_val
    }
}

pub fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut result = 0;

    for i in 0..8 {
        if (b >> i) & 1 == 1 {
            result = result ^ a;
        }

        a = mul_by_2(a);
    }

    result
}
