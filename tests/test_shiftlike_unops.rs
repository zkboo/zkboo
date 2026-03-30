mod common;

use crate::common::test_all_words::on_all_words_and_composites;
use crate::common::test_func::define_test_func;

const NUM_SAMPLES: usize = 100;

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

macro_rules! test_overflowing_shl {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr,
        $shifts: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {in_: $U},
                    [lo, hi],
                    |executor| {
                        let in_ = executor.input(in_);
                        (lo, hi) = in_.overflowing_shl(shift);
                    },
                    {
                        let in_ = WordLike::to_word(in_);
                        let width = (in_^in_).leading_zeros();
                        lo = in_.unbounded_shl(shift);
                        hi = if shift >= width {
                            in_.unbounded_shl(shift - width)
                        } else {
                            in_.unbounded_shr(width - shift)
                        };
                    },
                    shift : usize,
                    $shifts
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

macro_rules! test_shiftlike_on_all_words {
    (
        $num_samples: expr,
        $shifts: expr
    ) => {
        ::paste::paste! {
            #[test]
            fn test_unbounded_shl() {
                on_all_words_and_composites!(
                    test_parametric_unop!(unbounded_shl, $num_samples, in_, executor, in_.unbounded_shl(shift), WordLike::to_word(in_).unbounded_shl(shift), shift : usize, $shifts)
                );
            }
            #[test]
            fn test_unbounded_shr() {
                on_all_words_and_composites!(
                    test_parametric_unop!(unbounded_shr, $num_samples, in_, executor, in_.unbounded_shr(shift), WordLike::to_word(in_).unbounded_shr(shift), shift : usize, $shifts)
                );
            }

            #[test]
            fn test_rotate_left() {
                on_all_words_and_composites!(
                    test_parametric_unop!(rotate_left, $num_samples, in_, executor, in_.rotate_left(shift), WordLike::to_word(in_).rotate_left(shift), shift : usize, $shifts)
                );
            }

            #[test]
            fn test_rotate_right() {
                on_all_words_and_composites!(
                    test_parametric_unop!(rotate_right, $num_samples, in_, executor, in_.rotate_right(shift), WordLike::to_word(in_).rotate_right(shift), shift : usize, $shifts)
                );
            }
            #[test]
            fn test_overflowing_shl() {
                on_all_words_and_composites!(
                    test_overflowing_shl!(overflowing_shl, $num_samples, $shifts)
                );
            }
        }
    };
}

test_shiftlike_on_all_words!(
    NUM_SAMPLES,
    [
        0, 1, 2, 3, 4, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 48, 63, 64, 65, 96, 127, 128, 129,
        192, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025
    ]
);
