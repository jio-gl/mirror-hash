const DEFAULT_DEPTH: usize = 128;
const DEFAULT_SIZE: usize = 256;
const GATES: [&str; 2] = ["Toffoli", "Fredkin"];

pub struct Mirror256 {
    buffer: String,
    counter: usize,
    depth: usize,
    size: usize,
    last_hashes: Vec<Vec<u8>>,
    hashed: Vec<u8>,
}

impl Mirror256 {
    pub fn new(m: Option<&str>, depth: Option<usize>, size: Option<usize>, use_standard_state: bool) -> Self {
        let depth = depth.unwrap_or(DEFAULT_DEPTH);
        let size = size.unwrap_or(DEFAULT_SIZE);
        let mut last_hashes = Vec::new();

        if use_standard_state {
            // Initialize with standard state based on cubic roots of primes
            unimplemented!("Initializing with standard state is not implemented yet");
        } else {
            // Initialize with random hashes
            while last_hashes.len() < depth {
                last_hashes.push(Mirror256::random_hash(size));
            }
        }

        let mut hasher = Mirror256 {
            buffer: String::new(),
            counter: 0,
            depth,
            size,
            last_hashes,
            hashed: vec![0; size / 4],
        };

        if let Some(message) = m {
            hasher.update(message);
        }

        hasher
    }

    fn random_hash(size: usize) -> Vec<u8> {
        (0..size / 4).map(|_| rand::random::<u8>() & 0xF).collect()
    }

    fn update(&mut self, m: &str) {
        self.buffer.push_str(m);
        self.counter += m.len();

        while self.buffer.len() >= 32 {
            let hm = self.mirror256_process(&self.buffer[..32]);
            self.last_hashes.insert(0, hm.clone());
            self.last_hashes.truncate(self.depth);
            self.buffer = self.buffer[32..].to_string();
        }

        if !self.buffer.is_empty() || m.is_empty() {
            let padding = "A".repeat(32 - self.buffer.len());
            let hm = self.mirror256_process(&(self.buffer.clone() + &padding));
            self.buffer.clear();
            self.hashed = hm;
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        let mut hb = vec![0; self.size / 8];
        for i in 0..self.size / 8 {
            if i * 2 < self.hashed.len() {
                hb[i] = self.hashed[i * 2] << 4;
                if i * 2 + 1 < self.hashed.len() {
                    hb[i] |= self.hashed[i * 2 + 1];
                }
            }
        }
        hb
    }

    pub fn hexdigest(&self) -> String {
        let digest = self.digest();
        format!("0x{}", hex::encode(digest))
    }
    
    fn mirror256_process(&self, m: &str) -> Vec<u8> {
        let mut block = self.unpack(m);
        for layer in 0..self.depth {
            block = self.hash_layer_pass(layer, &block);
        }
        block
    }

    fn hash_layer_pass(&self, layer: usize, block: &[u8]) -> Vec<u8> {
        let layer_hash = &self.last_hashes[layer];
        let mut block = block.to_vec();

        // XOR with layer encoding to avoid 0 to 0 hashes
        for i in 0..self.size / 4 {
            block[i] ^= layer_hash[i];
        }

        for sublayer in &[true, false] {
            for gate_index in 0..self.size / 4 {
                let gate_type = if *sublayer {
                    layer_hash[gate_index] & 0x3
                } else {
                    (layer_hash[gate_index] & 0xC) >> 2
                };

                let gate_name = GATES[(gate_type & 1) as usize];
                let gate_symmetry = (gate_type >> 1) as usize;

                block = self.apply_gate(gate_index, gate_name, gate_symmetry, &block, *sublayer, layer);
            }
        }

        block
    }

    fn apply_gate(
        &self,
        gate_index: usize,
        gate_name: &str,
        gate_symmetry: usize,
        block: &[u8],
        first_sublayer: bool,
        layer: usize,
    ) -> Vec<u8> {
        let initial_offset = layer % 2;
        let wire1 = self.get_wire(gate_index, first_sublayer, initial_offset);
        let wire2 = self.get_wire(gate_index, first_sublayer, initial_offset + 1);
        let wire3 = self.get_wire(gate_index, first_sublayer, initial_offset + 2);
    
        let mut val1 = self.get_bit(block, wire1);
        let mut val2 = self.get_bit(block, wire2);
        let mut val3 = self.get_bit(block, wire3);
    
        match (gate_name, gate_symmetry) {
            ("Toffoli", 0) if (val1 & val2) == 1 => val3 ^= 1,
            ("Toffoli", 1) if (val2 & val3) == 1 => val1 ^= 1,
            ("Fredkin", 0) if val1 == 1 && val2 != val3 => std::mem::swap(&mut val2, &mut val3),
            ("Fredkin", 1) if val3 == 1 && val1 != val2 => std::mem::swap(&mut val1, &mut val2),
            _ => {}
        }
    
        let mut block = block.to_vec();
        block = self.set_bit(block, wire1, val1);
        block = self.set_bit(block, wire2, val2);
        block = self.set_bit(block, wire3, val3);
    
        block
    }

    fn get_wire(&self, gate_index: usize, first_sublayer: bool, offset: usize) -> usize {
        (gate_index * 4 + offset + if first_sublayer { 0 } else { 2 }) % self.size
    }

    fn get_bit(&self, block: &[u8], wire: usize) -> u8 {
        (block[wire / 4] >> (wire % 4)) & 1
    }

    fn set_bit(&self, mut block: Vec<u8>, wire: usize, bit: u8) -> Vec<u8> {
        let old_nib = block[wire / 4];
        let new_nib = (old_nib & !(1 << (wire % 4))) | ((bit as u8) << (wire % 4));
        block[wire / 4] = new_nib;
        block
    }

    fn unpack(&self, m: &str) -> Vec<u8> {
        let mut ret = vec![0; self.size / 4];
        for (i, b) in m.bytes().enumerate() {
            ret[i * 2] = b >> 4;
            ret[i * 2 + 1] = b & 0x0F;
        }
        ret
    }
}
