mod common;

use crate::common::test_all_words::test_on_all_words_and_composites;
use crate::common::test_func::define_test_func;
use zkboo::word::Word;

const NUM_SAMPLES: usize = 100;

macro_rules! test_wide_binop {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr,
        [$inl: ident, $inr: ident],
        $executor: ident,
        $expr: expr,
        $ref_expr: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {$inl: $U, $inr: $U},
                    [lo, hi],
                    |$executor| {
                        let $inl = $executor.input($inl);
                        let $inr = $executor.input($inr);
                        (lo, hi) = $expr;
                    },
                    {
                        (lo, hi) = $ref_expr;
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

macro_rules! test_wide_binop_const {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr,
        [$inl: ident, $inr: ident],
        $executor: ident,
        $expr: expr,
        $ref_expr: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName _const>],
                    $num_samples,
                    {$inl: $U, $inr: $U},
                    [lo, hi],
                    |$executor| {
                        let $inl = $executor.input($inl);
                        (lo, hi) = $expr;
                    },
                    {
                        (lo, hi) = $ref_expr;
                    }
                }
                [<$func _ $UName _const>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(
    overflowing_add,
    test_wide_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        {
            let (out, carry) = inl.overflowing_add(inr);
            (out, carry.into())
        },
        {
            let (out, carry) = inl.overflowing_add(inr);
            (out, carry as u8)
        }
    )
);

test_on_all_words_and_composites!(
    overflowing_add_const,
    test_wide_binop_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        {
            let (out, carry) = inl.overflowing_add_const(inr);
            (out, carry.into())
        },
        {
            let (out, carry) = inl.overflowing_add(inr);
            (out, carry as u8)
        }
    )
);

test_on_all_words_and_composites!(
    overflowing_sub,
    test_wide_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        {
            let (out, borrow) = inl.overflowing_sub(inr);
            (out, borrow.into())
        },
        {
            let (out, borrow) = inl.overflowing_sub(inr);
            (out, borrow as u8)
        }
    )
);

test_on_all_words_and_composites!(
    overflowing_sub_const,
    test_wide_binop_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        {
            let (out, borrow) = inl.overflowing_sub_const(inr);
            (out, borrow.into())
        },
        {
            let (out, borrow) = inl.overflowing_sub(inr);
            (out, borrow as u8)
        }
    )
);

test_on_all_words_and_composites!(
    wide_mul,
    test_wide_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.wide_mul(inr),
        inl.wide_mul(inr)
    )
);

test_on_all_words_and_composites!(
    wide_mul_const,
    test_wide_binop_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.wide_mul_const(inr),
        inl.wide_mul(inr)
    )
);
