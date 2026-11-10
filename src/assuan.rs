pub const MAX_LINE: usize = 1000;
pub const MAX_DATA: usize = MAX_LINE - 4; // D prefix and CRLF.

pub fn encoded_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .map(|byte| match byte {
            b'%' | b'\r' | b'\n' => 3,
            _ => 1,
        })
        .sum()
}
