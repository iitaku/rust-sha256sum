use std::io;
use std::os;

fn gather_in_be(x: [u8, ..4]) -> u32 {
    (x[0].to_u32().unwrap() << 24) |
        (x[1].to_u32().unwrap() << 16) |
        (x[2].to_u32().unwrap() <<  8) |
        (x[3].to_u32().unwrap() <<  0)
}

fn scatter_in_be(x: u32) -> [u8, ..4] {
    [((x & 0xFF000000) >> 24).to_u8().unwrap(),
    ((x & 0x00FF0000) >> 16).to_u8().unwrap(),
    ((x & 0x0000FF00) >>  8).to_u8().unwrap(),
    ((x & 0x000000FF) >>  0).to_u8().unwrap()]
}

fn print_arr_u8(x: &[u8]) {
    println!("[");
    for i in range(0, x.len()) {
        print!(" 0x{:02x}", x[i]);
        if i % 16 == 15 {
            println!("");
        }
    }
    println!("]");
}

fn print_arr_u32(x: &[u32]) {
    println!("[");
    for i in range(0, x.len()) {
        print!(" 0x{:08x}", x[i]);
        if i % 8 == 7 {
            println!("");
        }
    }
    println!("]");
}

fn sha256sum(target: &mut Vec<u8>) -> String {

    // first 32 bits of fractional parts of the square roots of the first 8 primes 2..19
    let mut hs : [u32, ..8]  = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    ];

    // first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
    static KEYS : [u32, ..64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    //
    // pre-process
    //

    let msg_len = target.len() as u32;

    // stop bits
    target.push(0x80);

    // zero-padding
    for _ in range(0, 64-(target.len() % 64)-4) {
        target.push(0x0);
    }

    // message length in bit, Big-Endian
    target.push_all(scatter_in_be(msg_len*8));

    //
    // hash each 512bit
    //
    let target_s = target.as_slice();

    let mut ws : [u32, ..64] = [0, ..64];
    for i in range(0, target.len() / 64) {

        // copy first 512bit
        for j in range(0, 16u) {
            ws[j] = gather_in_be([target_s[(i*16+j)*4+0], target_s[(i*16+j)*4+1], target_s[(i*16+j)*4+2], target_s[(i*16+j)*4+3]]);
        }

        // extend left
        for j in range(16, 64u) {
            let s0 = ws[j-15].rotate_right( 7) ^ ws[j-15].rotate_right(18) ^ (ws[j-15] >>  3);
            let s1 = ws[j- 2].rotate_right(17) ^ ws[j- 2].rotate_right(19) ^ (ws[j- 2] >> 10);
            ws[j] = ws[j-16] + s0 + ws[j-7] + s1;
        }

        let mut a = hs[0];
        let mut b = hs[1];
        let mut c = hs[2];
        let mut d = hs[3];
        let mut e = hs[4];
        let mut f = hs[5];
        let mut g = hs[6];
        let mut h = hs[7];

        for j in range(0, 64u) {

            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h + s1 + ch + KEYS[j] + ws[j];
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hs[0] += a;
        hs[1] += b;
        hs[2] += c;
        hs[3] += d;
        hs[4] += e;
        hs[5] += f;
        hs[6] += g;
        hs[7] += h;
    }

    format!("{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}", hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7])
}

fn main() {

    let mut target : Vec<u8>;
    let mut target_name : String;

    if os::args().len() == 1 {
        target_name = String::from_str("-");
        target = io::stdin().read_to_end().ok().expect("Failed to read stdin");
    } else {
        target_name = os::args()[1].clone();
        let p = Path::new(target_name.clone());
        target = io::File::open_mode(&p, io::Open, io::ReadWrite).ok().expect("Failed to open file")
                          .read_to_end().ok().expect("Failed to read file");
    }

    println!("{}  {}", sha256sum(&mut target), target_name);
}
