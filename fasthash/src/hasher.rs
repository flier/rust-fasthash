pub trait Hasher {
    type Value;
    type Seed: Default;

    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: Self::Seed) -> Self::Value;

    fn hash<T: AsRef<[u8]>>(bytes: &T) -> Self::Value {
        Self::hash_with_seed(bytes, Default::default())
    }
}

#[macro_export]
macro_rules! fasthash {
    ($hasher:ident, $hash:ident) => (
        #[derive(Default, Clone)]
        pub struct $hasher {
            seed: <$hash as $crate::hasher::Hasher>::Seed,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            pub fn new() -> Self {
                $hasher {
                    seed: Default::default(),
                    bytes: Vec::with_capacity(16),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::Hasher>::Seed) -> Self {
                $hasher {
                    seed: seed,
                    bytes: Vec::with_capacity(16),
                }
            }
        }

        impl ::std::hash::Hasher for $hasher {
            fn finish(&self) -> u64 {
                $hash::hash_with_seed(&self.bytes, self.seed).into()
            }
            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes)
            }
        }
    )
}
