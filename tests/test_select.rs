mod common;

use crate::common::test_all_words::test_on_all_words_and_composites;
use crate::common::test_func::define_test_func;
use zkboo::word::Word;

const NUM_SAMPLES: usize = 100;

macro_rules! test_select {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {cond: $U, then: $U, else_: $U},
                    [out],
                    |executor| {
                        let cond = executor.input(cond).lsb();
                        let then = executor.input(then);
                        let else_ = executor.input(else_);
                        out = cond.select(then, else_);
                    },
                    {
                        out = if cond.lsb() {then} else {else_}
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(select, test_select!(NUM_SAMPLES));

macro_rules! test_select_var_const {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {cond: $U, then: $U, else_: $U},
                    [out],
                    |executor| {
                        let cond = executor.input(cond).lsb();
                        let then = executor.input(then);
                        out = cond.select_var_const(then, else_);
                    },
                    {
                        out = if cond.lsb() {then} else {else_}
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(select_var_const, test_select_var_const!(NUM_SAMPLES));

macro_rules! test_select_const_var {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {cond: $U, then: $U, else_: $U},
                    [out],
                    |executor| {
                        let cond = executor.input(cond).lsb();
                        let else_ = executor.input(else_);
                        out = cond.select_const_var(then, else_);
                    },
                    {
                        out = if cond.lsb() {then} else {else_}
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(select_const_var, test_select_const_var!(NUM_SAMPLES));

macro_rules! test_select_const_const {
    (
        {$($UName: ident : ($_W: ty, $_N: expr, $U: ty)),* $(,)?},
        $func: ident,
        $num_samples: expr
    ) => {
        ::paste::paste! {
            $(
                define_test_func! {
                    [<$func _ $UName>],
                    $num_samples,
                    {cond: $U, then: $U, else_: $U},
                    [out],
                    |executor| {
                        let cond = executor.input(cond).lsb();
                        out = cond.select_const_const(then, else_);
                    },
                    {
                        out = if cond.lsb() {then} else {else_}
                    }
                }
                [<$func _ $UName>]();
            )*
        }
    };
}

test_on_all_words_and_composites!(select_const_const, test_select_const_const!(NUM_SAMPLES));
