//! Growable FIFO byte buffer with amortised O(1) consumption (no copy of the remainder per read).

#[derive(Debug, Default, Clone)]
pub struct ByteBuffer {
    storage: Vec<u8>,
    head: usize,
}

impl ByteBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.storage.len() - self.head
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.storage.extend_from_slice(bytes);
    }

    /// Removes and returns exactly `n` bytes, or `None` if fewer are buffered.
    pub fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.len() < n {
            return None;
        }
        let out = self.storage[self.head..self.head + n].to_vec();
        self.head += n;
        self.compact_if_needed();
        Some(out)
    }

    pub fn take_all(&mut self) -> Vec<u8> {
        self.take(self.len()).unwrap_or_default()
    }

    /// Removes everything up to and including `marker`; returns the bytes before it.
    pub fn take_up_to(&mut self, marker: &[u8]) -> Option<Vec<u8>> {
        if marker.is_empty() || self.len() < marker.len() {
            return None;
        }
        let pos = self.storage[self.head..].windows(marker.len()).position(|w| w == marker)? + self.head;
        let out = self.storage[self.head..pos].to_vec();
        self.head = pos + marker.len();
        self.compact_if_needed();
        Some(out)
    }

    fn compact_if_needed(&mut self) {
        if self.head == self.storage.len() {
            self.storage.clear();
            self.head = 0;
        } else if self.head > 1 << 16 && self.head * 2 > self.storage.len() {
            self.storage.drain(..self.head);
            self.head = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_exact_and_short() {
        let mut b = ByteBuffer::new();
        b.append(&[1, 2, 3, 4, 5]);
        assert_eq!(b.take(2), Some(vec![1, 2]));
        assert_eq!(b.len(), 3);
        assert_eq!(b.take(4), None);
        assert_eq!(b.take(0), Some(vec![]));
        assert_eq!(b.take_all(), vec![3, 4, 5]);
        assert!(b.is_empty());
        assert_eq!(b.take_all(), Vec::<u8>::new());
    }

    #[test]
    fn take_up_to_marker() {
        let mut b = ByteBuffer::new();
        b.append(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody");
        assert_eq!(b.take_up_to(b"\r\n\r\n").unwrap(), b"HTTP/1.1 200 OK\r\nA: b");
        assert_eq!(b.take_up_to(b"\r\n\r\n"), None);
        assert_eq!(b.take_all(), b"body");
    }

    #[test]
    fn marker_edge_cases() {
        let mut b = ByteBuffer::new();
        assert_eq!(b.take_up_to(b""), None);
        b.append(b"ab");
        assert_eq!(b.take_up_to(b"abc"), None);
        assert_eq!(b.take_up_to(b"ab"), Some(vec![]));
        assert!(b.is_empty());
    }

    #[test]
    fn marker_split_across_appends() {
        let mut b = ByteBuffer::new();
        b.append(b"x\r\n");
        assert_eq!(b.take_up_to(b"\r\n\r\n"), None);
        b.append(b"\r\ny");
        assert_eq!(b.take_up_to(b"\r\n\r\n").unwrap(), b"x");
    }

    #[test]
    fn compacts_without_losing_data() {
        let mut b = ByteBuffer::new();
        b.append(&vec![7u8; 200_000]);
        b.append(&[1, 2, 3]);
        assert_eq!(b.take(150_000).unwrap().len(), 150_000);
        assert_eq!(b.len(), 50_003);
        assert_eq!(b.take(50_000).unwrap().len(), 50_000);
        assert_eq!(b.take_all(), vec![1, 2, 3]);
    }
}
