mod common;

use crate::common::test_all_words::{
    test_on_all_composites, test_on_all_words, test_on_all_words_and_composites,
};
use core::array;

const NUM_SAMPLES: usize = 100;

macro_rules! test_into_le_words {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_: $U
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_ = frontend.input(self.in_);
                            let out_array = in_.into_le_words();
                            out_array.into_iter().for_each(|out| frontend.output(out));
                        }
                    }
                    let seed = 0u64;
                    let mut iter_in_ = test_vec::<_, _, $U>($num_samples, seed).into_iter();
                    for _  in 0..$num_samples {
                        // Test execution:
                        let in_ = iter_in_.next().unwrap();
                        let circuit = TestCircuit {in_};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out_array = in_.to_word().to_le_words();
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(out_array.into_iter().flat_map(|out| WordLike::to_word(out).to_le_words()));
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(into_le_words, test_into_le_words!(NUM_SAMPLES));

macro_rules! test_from_le_words {
    (
        {$($UName: ident : ($W: ty, $N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend, WordRef},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_array: [$W; $N]
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_array: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_array = self.in_array.map(|in_| frontend.input(in_));
                            let out = WordRef::<B, $W, $N>::from_le_words(in_array);
                            frontend.output(out);
                        }
                    }
                    let mut seed = 0u64;
                    #[allow(non_snake_case)]
                    let mut iter_in__array: [_; $N] = array::from_fn(|_|{
                        seed += 1;
                        test_vec::<_, _, $W>($num_samples, seed).into_iter()
                    });
                    for _  in 0..$num_samples {
                        let in_array: [_; $N] = array::from_fn(|i|{
                            iter_in__array[i].next().unwrap()
                        });
                        // Test execution:
                        let circuit = TestCircuit {in_array};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out = $U::from_le_words(in_array);
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(WordLike::to_word(out).to_le_words());
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_composites!(from_le_words, test_from_le_words!(NUM_SAMPLES));

macro_rules! test_into_le_bytes {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_: $U
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_ = frontend.input(self.in_);
                            let out_vec = in_.into_le_bytes();
                            out_vec.into_iter().for_each(|out| frontend.output(out));
                        }
                    }
                    let seed = 0u64;
                    let mut iter_in_ = test_vec::<_, _, $U>($num_samples, seed).into_iter();
                    for _  in 0..$num_samples {
                        let in_ = iter_in_.next().unwrap();
                        // Test execution:
                        let circuit = TestCircuit {in_};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out_vec = in_.to_word().to_le_bytes();
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(out_vec.into_iter().flat_map(|out| WordLike::to_word(out).to_le_words()));
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words!(into_le_bytes, test_into_le_bytes!(NUM_SAMPLES));

macro_rules! test_into_be_bytes {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_: $U
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_ = self.in_;
                            let in_ = frontend.input(in_);
                            let out_vec = in_.into_be_bytes();
                            out_vec.into_iter().for_each(|out| frontend.output(out));
                        }
                    }
                    let seed = 0u64;
                    let mut iter_in_ = test_vec::<_, _, $U>($num_samples, seed).into_iter();
                    for _  in 0..$num_samples {
                        let in_ = iter_in_.next().unwrap();
                        // Test execution:
                        let circuit = TestCircuit {in_};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out_vec = in_.to_word().to_be_bytes();
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(out_vec.into_iter().flat_map(|out| WordLike::to_word(out).to_le_words()));
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words!(into_be_bytes, test_into_be_bytes!(NUM_SAMPLES));

macro_rules! test_from_le_bytes {
    (
        {$($UName: ident : ($W: ty, $N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend, WordRef},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_array: Vec<u8>
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_array: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_array = self.in_array.clone().into_iter().map(|in_| frontend.input(in_)).collect::<Vec<_>>();
                            let out = WordRef::<B, $W, $N>::from_le_bytes(in_array).unwrap();
                            frontend.output(out);
                        }
                    }
                    let seed = 0u64;
                    let mut iter_in_ = test_vec::<_, _, $U>($num_samples, seed).into_iter();
                    for _  in 0..$num_samples {
                        let in_vec = iter_in_.next().unwrap().to_le_bytes().to_vec();
                        // Test execution:
                        let circuit = TestCircuit {in_array: in_vec.clone()};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out = $U::from_le_bytes(in_vec.try_into().unwrap());
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(WordLike::to_word(out).to_le_words());
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words!(from_le_bytes, test_from_le_bytes!(NUM_SAMPLES));

macro_rules! test_from_be_bytes {
    (
        {$($UName: ident : ($W: ty, $N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend, WordRef},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_array: Vec<u8>
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_array: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_array = self.in_array.clone().into_iter().map(|in_| frontend.input(in_)).collect::<Vec<_>>();
                            let out = WordRef::<B, $W, $N>::from_be_bytes(in_array).unwrap();
                            frontend.output(out);
                        }
                    }
                    let seed = 0u64;
                    let mut iter_in_ = test_vec::<_, _, $U>($num_samples, seed).into_iter();
                    for _  in 0..$num_samples {
                        let in_vec = iter_in_.next().unwrap().to_le_bytes().to_vec();
                        // Test execution:
                        let circuit = TestCircuit {in_array: in_vec.clone()};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out = $U::from_be_bytes(in_vec.try_into().unwrap());
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(WordLike::to_word(out).to_le_words());
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words!(from_be_bytes, test_from_be_bytes!(NUM_SAMPLES));

macro_rules! test_mask {
    (
        {$($UName: ident : ($W: ty, $N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                fn [<$func _ $UName>](){
                    #[allow(unused_imports)]
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend, WordRef},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Word, Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                    type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_: u8
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                            let in_ = frontend.input(self.in_).lsb();
                            let out = WordRef::<B, $W, $N>::mask(in_);
                            frontend.output(out);
                        }
                    }
                    let seed = 0u64;
                    let mut iter_in_ = test_vec::<_, _, u8>($num_samples, seed).into_iter();
                    for _  in 0..$num_samples {
                        // Test execution:
                        let in_ = iter_in_.next().unwrap();
                        let circuit = TestCircuit {in_};
                        let outputs = exec::<_, WP>(&circuit);
                        // Reference execution:
                        let out = if in_ & 1u8 != 0 {$U::MAX} else {$U::ZERO};
                        let mut expected_outputs = Words::new();
                        expected_outputs.as_vec_mut().extend(WordLike::to_word(out).to_le_words());
                        // Ensure matching output words:
                        assert_eq!(outputs, expected_outputs);
                        // Test proof generation:
                        test_proof(&circuit);
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(mask, test_mask!(NUM_SAMPLES));

macro_rules! test_cast_fixed_in_out {
    (
        [$S: ty, $T: ty],
        $num_samples: expr
    ) => {
        ::paste::paste! {
            fn [<cast _ $S _ $T>](){
                    use zkboo::{
                        circuit::Circuit,
                        backend::{Backend, Frontend},
                        executor::{exec, OwnedFlexibleWordPool},
                        word::{Word, Words, WordLike},
                    };
                    use $crate::common::rand_words::test_vec;
                    use $crate::common::proofs::test_proof;
                type WP = OwnedFlexibleWordPool<usize>;
                    struct TestCircuit{
                        in_: $S
                    }
                    impl Default for TestCircuit {
                        fn default() -> Self {
                            Self {
                                in_: Default::default(),
                            }
                        }
                    }
                    impl Circuit for TestCircuit {
                        fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
                        let in_ = frontend.input(self.in_);
                        // let out = WordRef::<B, $S, 1>::cast::<$T>(in_);
                        let out = in_.cast::<$T>();
                        frontend.output(out);
                        }
                    }
                let seed = 0u64;
                let mut iter_in_ = test_vec::<_, _, $S>($num_samples, seed).into_iter();
                for _  in 0..$num_samples {
                    // Test execution:
                    let in_ = iter_in_.next().unwrap();
                    let circuit = TestCircuit {in_};
                    let outputs = exec::<_, WP>(&circuit);
                    // Reference execution:
                    let out = in_.cast::<$T>();
                    let mut expected_outputs = Words::new();
                    expected_outputs.as_vec_mut().extend(WordLike::to_word(out).to_le_words());
                    // Ensure matching output words:
                    assert_eq!(outputs, expected_outputs);
                    // Test proof generation:
                    test_proof(&circuit);
                }
            }
            [<cast _ $S _ $T>]();
        }
    };
}

macro_rules! test_cast_fixed_in {
    (
        $S: ty,
        $num_samples: expr
    ) => {
        test_cast_fixed_in_out!([$S, u8], $num_samples);
        test_cast_fixed_in_out!([$S, u16], $num_samples);
        test_cast_fixed_in_out!([$S, u32], $num_samples);
        test_cast_fixed_in_out!([$S, u64], $num_samples);
        test_cast_fixed_in_out!([$S, u128], $num_samples);
    };
}

macro_rules! test_cast {
    (
        $num_samples: expr
    ) => {
        #[test]
        fn test_cast() {
            test_cast_fixed_in!(u8, $num_samples);
            test_cast_fixed_in!(u16, $num_samples);
            test_cast_fixed_in!(u32, $num_samples);
            test_cast_fixed_in!(u64, $num_samples);
            test_cast_fixed_in!(u128, $num_samples);
        }
    };
}

test_cast!(NUM_SAMPLES);
