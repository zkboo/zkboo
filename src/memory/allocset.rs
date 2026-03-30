// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of an allocation set data structure,
//! used internally by [MemoryManager](crate::memory::MemoryManager)s to efficiently track
//! allocated and free words in the backend.

use alloc::vec::Vec;

// The current implementation of AllocSet uses 64-bit blocks for its internal bitset.
// The block size is a balancing exercise between three factors:
// - How frequently the block vector needs to be extended (every 64 words)
// - How much memory is wasted by partially filled blocks (up to 63 bits)
// - How expensive it is to find the next free bit (bitwise not and trailing zeros on 64-bit uints)
// All of these are marginal concerns, and 64-bit blocks seem like a reasonable compromise.

/// Allocation set data structure, for use by [MemoryManager](crate::memory::MemoryManager)s.
#[derive(Debug, Clone)]
pub struct AllocSet {
    blocks: Vec<u64>,
    size: usize,
    alloc_count: usize,
    hint_block_index: usize,
}

impl AllocSet {
    /// Creates a new empty allocation set with the given initial capacity for its block vector.
    pub fn with_capacity(capacity: usize) -> Self {
        let size = 0;
        let num_blocks = (capacity + 63) / 64;
        return AllocSet {
            blocks: Vec::with_capacity(num_blocks),
            size,
            alloc_count: size,
            hint_block_index: 0,
        };
    }

    /// Number of words tracked by the allocation set.
    pub fn size(&self) -> usize {
        return self.size;
    }

    /// Number of currently allocated words.
    pub fn alloc_count(&self) -> usize {
        return self.alloc_count;
    }

    /// Whether all words are currently allocated.
    pub fn is_full(&self) -> bool {
        return self.alloc_count == self.size;
    }

    /// Push a new word into the set, marked as allocated.
    fn push_allocated(&mut self) -> usize {
        let current_size = self.size;
        if current_size % 64 == 0 {
            self.blocks.push(u64::MAX);
        }
        self.size += 1;
        self.alloc_count += 1;
        return current_size;
    }

    /// Free the word by given index in the set.
    /// Panics if the word is already free.
    pub fn free(&mut self, index: usize) {
        assert!(index < self.size, "Invalid index detected");
        let block_index = index / 64;
        let mask = 1 << (index % 64);
        assert!(
            (self.blocks[block_index] & mask) != 0,
            "Double free detected"
        );
        self.hint_block_index = block_index;
        self.blocks[block_index] &= !mask;
        self.alloc_count -= 1;
    }

    /// Attempts to allocate a currently free word in the set.
    pub fn alloc(&mut self) -> usize {
        let idx = self.try_alloc();
        if let Some(idx) = idx {
            return idx;
        }
        return self.push_allocated();
    }

    /// Attempts to allocate a currently free word in the set.
    /// Returns [None] if all words are allocated, otherwise returns the allocated index.
    fn try_alloc(&mut self) -> Option<usize> {
        if self.is_full() {
            return None;
        }
        let num_blocks = self.blocks.len();
        let mut block_index = self.hint_block_index;
        loop {
            let block = self.blocks[block_index];
            if block == u64::MAX {
                block_index = (block_index + 1) % num_blocks;
                continue;
            }
            self.hint_block_index = block_index;
            let free_bit_idx = (!block).trailing_zeros() as usize;
            self.blocks[block_index] |= 1u64 << free_bit_idx;
            self.alloc_count += 1;
            return Some(64 * block_index + free_bit_idx);
        }
    }

    /// Clears the allocation set, marking all words as free but retaining the allocated capacity.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.size = 0;
        self.alloc_count = 0;
        self.hint_block_index = 0;
    }

    // /// Creates a new allocated set with the given size, all words marked as allocated.
    // pub fn new_allocated(size: usize) -> Self {
    //     let num_blocks = (size + 63) / 64;
    //     return AllocSet {
    //         blocks: vec![u64::MAX; num_blocks],
    //         size,
    //         alloc_count: size,
    //         hint_block_index: 0,
    //     };
    // }

    // pub fn reserve(&mut self, additional: usize) {
    //     let num_blocks = self.blocks.capacity();
    //     let capacity = num_blocks * 64;
    //     let new_capacity = capacity + additional;
    //     let new_num_blocks = (new_capacity + 63) / 64;
    //     if new_num_blocks > num_blocks {
    //         self.blocks.reserve_exact(new_num_blocks - num_blocks);
    //     }
    // }

    // pub fn resize(&mut self, new_size: usize) {
    //     let num_blocks = self.blocks.len();
    //     let size = num_blocks * 64;
    //     if new_size == size {
    //         return;
    //     }
    //     let new_num_blocks = (new_size + 63) / 64;
    //     if new_size < size {
    //         let current_mask = !(u64::MAX << (size % 64));
    //         let new_mask = !(u64::MAX << (new_size % 64));
    //         let last_block = self.blocks[num_blocks - 1];
    //         if new_num_blocks == num_blocks {
    //             // Resizing happens entirely within current last block, check allocated words there:
    //             assert_eq!(
    //                 last_block & current_mask & !new_mask,
    //                 0,
    //                 "Cannot resize: Allocated words would be affected by shrinking."
    //             );
    //         } else {
    //             // Check allocated words in current last block:
    //             assert_eq!(
    //                 last_block & current_mask,
    //                 0,
    //                 "Cannot resize: Allocated words would be affected by shrinking."
    //             );
    //             // Check allocated words in all intermediate blocks, if any:
    //             for b in new_num_blocks + 1..(num_blocks - 1) {
    //                 assert_eq!(
    //                     self.blocks[b], 0,
    //                     "Cannot resize: Allocated words would be affected by shrinking."
    //                 )
    //             }
    //             // Check allocated words in new last block:
    //             if new_num_blocks > 0 {
    //                 let new_last_block = self.blocks[new_num_blocks - 1];
    //                 assert_eq!(
    //                     new_last_block & !new_mask,
    //                     0,
    //                     "Cannot resize: Allocated words would be affected by shrinking."
    //                 );
    //             }
    //         }
    //     }
    //     self.blocks.resize(new_num_blocks, u64::MAX);
    //     self.size = new_size;
    // }
}

impl Default for AllocSet {
    /// Creates a new empty allocation set with no initial capacity.
    fn default() -> Self {
        return Self::with_capacity(0);
    }
}

impl Drop for AllocSet {
    /// Asserts that there are no allocated words in the set when it is dropped, to catch leaks.
    fn drop(&mut self) {
        assert!(
            self.alloc_count == 0,
            "Memory leak detected: {} allocated words were not freed.",
            self.alloc_count
        );
    }
}
