mod common;

use crate::common::test_all_words::test_on_all_words_and_composites;
use crate::common::test_func::define_test_func;
use zkboo::word::Word;

const NUM_SAMPLES: usize = 100;

macro_rules! test_comparison {
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
                        out = $expr.into();
                    },
                    {
                        out = ($ref_expr) as u8;
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

macro_rules! test_comparison_const {
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
                        out = $expr.into();
                    },
                    {
                        out = ($ref_expr) as u8;
                    }
                }
                [<$func _ $UName _const>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(
    lt,
    test_comparison!(NUM_SAMPLES, [inl, inr], executor, inl.lt(inr), inl.lt(inr))
);

test_on_all_words_and_composites!(
    lt_const,
    test_comparison_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.lt_const(inr),
        inl.lt(inr)
    )
);

test_on_all_words_and_composites!(
    le,
    test_comparison!(NUM_SAMPLES, [inl, inr], executor, inl.le(inr), inl.le(inr))
);

test_on_all_words_and_composites!(
    le_const,
    test_comparison_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.le_const(inr),
        inl.le(inr)
    )
);

test_on_all_words_and_composites!(
    gt,
    test_comparison!(NUM_SAMPLES, [inl, inr], executor, inl.gt(inr), inl.gt(inr))
);

test_on_all_words_and_composites!(
    gt_const,
    test_comparison_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.gt_const(inr),
        inl.gt(inr)
    )
);

test_on_all_words_and_composites!(
    ge,
    test_comparison!(NUM_SAMPLES, [inl, inr], executor, inl.ge(inr), inl.ge(inr))
);

test_on_all_words_and_composites!(
    ge_const,
    test_comparison_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.ge_const(inr),
        inl.ge(inr)
    )
);

test_on_all_words_and_composites!(
    eq,
    test_comparison!(NUM_SAMPLES, [inl, inr], executor, inl.eq(inr), inl.eq(inr))
);

test_on_all_words_and_composites!(
    eq_const,
    test_comparison_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.eq_const(inr),
        inl.eq(inr)
    )
);

test_on_all_words_and_composites!(
    ne,
    test_comparison!(NUM_SAMPLES, [inl, inr], executor, inl.ne(inr), inl.ne(inr))
);

test_on_all_words_and_composites!(
    ne_const,
    test_comparison_const!(
        NUM_SAMPLES,
        [inl, inr],
        executor,
        inl.ne_const(inr),
        inl.ne(inr)
    )
);
