mod common;

use crate::common::test_all_words::{test_on_all_composites, test_on_all_words_and_composites};
use crate::common::test_func::define_test_func;
use zkboo::word::Word;

const NUM_SAMPLES: usize = 100;

macro_rules! test_unop {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr,
        $in_: ident,
        $executor: ident,
        $expr: expr,
        $ref_expr: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {$in_: $U},
                    [out],
                    |$executor| {
                        let $in_ = $executor.input($in_);
                        out = $expr;
                    },
                    {
                        out = $ref_expr;
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(not, test_unop!(NUM_SAMPLES, in_, executor, !in_, !in_));

test_on_all_words_and_composites!(
    reverse_bits,
    test_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.reverse_bits(),
        in_.reverse_bits()
    )
);

test_on_all_words_and_composites!(
    swap_bytes,
    test_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.swap_bytes(),
        in_.swap_bytes()
    )
);

test_on_all_words_and_composites!(
    neg,
    test_unop!(NUM_SAMPLES, in_, executor, -in_, in_.wrapping_neg())
);

test_on_all_composites!(
    lsw,
    test_unop!(NUM_SAMPLES, in_, executor, in_.lsw(), in_.lsw())
);

test_on_all_composites!(
    msw,
    test_unop!(NUM_SAMPLES, in_, executor, in_.msw(), in_.msw())
);

test_on_all_words_and_composites!(
    lsb,
    test_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.lsb().into(),
        in_.lsb() as u8
    )
);

test_on_all_words_and_composites!(
    msb,
    test_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.msb().into(),
        in_.msb() as u8
    )
);

test_on_all_words_and_composites!(
    is_zero,
    test_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.is_zero().into(),
        in_.is_zero() as u8
    )
);

test_on_all_words_and_composites!(
    is_nonzero,
    test_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.is_nonzero().into(),
        in_.is_nonzero() as u8
    )
);

macro_rules! test_parametric_unop {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr,
        $in_: ident,
        $executor: ident,
        $expr: expr,
        $ref_expr: expr,
        $param_name: ident : $param_type: ty,
        $param_values: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {$in_: $U},
                    [out],
                    |$executor| {
                        let $in_ = $executor.input($in_);
                        out = $expr;
                    },
                    {
                        out = $ref_expr;
                    },
                    $param_name : $param_type,
                    $param_values
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_composites!(
    word_at,
    test_parametric_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.word_at(idx),
        in_.word_at(idx),
        idx : usize,
        [
            0, 1, 2, 3, 4, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 48, 63, 64, 65, 96, 127, 128,
            129, 192, 255, 256, 257, 511, 512, 513,
        ]
    )
);

test_on_all_words_and_composites!(
    bit_at,
    test_parametric_unop!(
        NUM_SAMPLES,
        in_,
        executor,
        in_.bit_at(idx).into(),
        in_.bit_at(idx) as u8,
        idx : usize,
        [
            0, 1, 2, 3, 4, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 48, 63, 64, 65, 96, 127, 128,
            129, 192, 255, 256, 257, 511, 512, 513,
        ]
    )
);
