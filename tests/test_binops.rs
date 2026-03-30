mod common;

use crate::common::test_all_words::test_on_all_words_and_composites;
use crate::common::test_func::define_test_func;
use zkboo::word::Word;

const NUM_SAMPLES: usize = 100;

macro_rules! test_binop {
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
                    [out],
                    |$executor| {
                        let $inl = $executor.input($inl);
                        let $inr = $executor.input($inr);
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

macro_rules! test_binop_const {
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
                    [out],
                    |$executor| {
                        let $inl = $executor.input($inl);
                        out = $expr;
                    },
                    {
                        out = $ref_expr;
                    }
                }
                [<$func _ $UName _const>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(
    bitxor,
    test_binop!(NUM_SAMPLES, [inl, inr], executor, inl ^ inr, inl ^ inr)
);

test_on_all_words_and_composites!(
    bitxor_const,
    test_binop_const!(NUM_SAMPLES, [inl, inr], executor, inl ^ inr, inl ^ inr)
);

test_on_all_words_and_composites!(
    bitand,
    test_binop!(NUM_SAMPLES, [inl, inr], executor, inl & inr, inl & inr)
);

test_on_all_words_and_composites!(
    bitand_const,
    test_binop_const!(NUM_SAMPLES, [inl, inr], executor, inl & inr, inl & inr)
);

test_on_all_words_and_composites!(
    bitor,
    test_binop!(NUM_SAMPLES, [inl, inr], executor, inl | inr, inl | inr)
);

test_on_all_words_and_composites!(
    bitor_const,
    test_binop_const!(NUM_SAMPLES, [inl, inr], executor, inl | inr, inl | inr)
);

test_on_all_words_and_composites!(
    carry_false,
    test_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.carry(inr, false),
        inl.carry(inr, false).0
    )
);

test_on_all_words_and_composites!(
    carry_true,
    test_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.carry(inr, true),
        inl.carry(inr, true).0
    )
);

test_on_all_words_and_composites!(
    wrapping_add,
    test_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl + inr,
        inl.wrapping_add(inr)
    )
);

test_on_all_words_and_composites!(
    wrapping_add_const,
    test_binop_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl + inr,
        inl.wrapping_add(inr)
    )
);

test_on_all_words_and_composites!(
    wrapping_sub,
    test_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl - inr,
        inl.wrapping_sub(inr)
    )
);

test_on_all_words_and_composites!(
    wrapping_sub_const,
    test_binop_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl - inr,
        inl.wrapping_sub(inr)
    )
);

test_on_all_words_and_composites!(
    wrapping_mul,
    test_binop!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl * inr,
        inl.wrapping_mul(inr)
    )
);

test_on_all_words_and_composites!(
    wrapping_mul_const,
    test_binop_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl * inr,
        inl.wrapping_mul(inr)
    )
);
